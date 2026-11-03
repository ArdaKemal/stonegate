#!/usr/bin/env python3
"""Exercise access logs, compression, virtual hosts, response policies,
the reverse proxy, certificate reload, draining shutdown, encrypted HTTP/3 keys, and account
switching through the Stonegate executable."""
import base64
import contextlib
import getpass
import gzip
import hashlib
import http.client
import http.server
import os
import pathlib
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

SERVER = str(pathlib.Path(sys.argv[1]).resolve())
CURL = shutil.which("curl")
try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings
except ImportError:
    h2 = None
CURL_H3 = bool(CURL) and "HTTP3" in subprocess.run(
    [CURL, "--version"], capture_output=True, text=True, check=True).stdout


def free_ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]


def fetch(port, path="/", headers=None, method="GET", tls=False, connection=None):
    owned = connection is None
    if owned:
        connection = (http.client.HTTPSConnection("127.0.0.1", port, timeout=5,
                      context=ssl._create_unverified_context()) if tls else
                      http.client.HTTPConnection("127.0.0.1", port, timeout=5))
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        fields = {name.lower(): value for name, value in response.getheaders()}
        return response.status, fields, response.read()
    finally:
        if owned:
            connection.close()


def peer_certificate(port):
    context = ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            return tls.getpeercert(binary_form=True)


def certificate_der(path):
    return ssl.PEM_cert_to_DER_cert(pathlib.Path(path).read_text())


def openssl(*arguments):
    result = subprocess.run(["openssl", *arguments], capture_output=True, text=True)
    assert result.returncode == 0, (arguments, result.stderr)


def make_certificate(directory, name, password=None):
    key, cert = directory / f"{name}-key.pem", directory / f"{name}-cert.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert))
    if password:
        plain = key.with_suffix(".plain")
        key.rename(plain)
        openssl("pkey", "-in", str(plain), "-aes-256-cbc", "-passout", f"pass:{password}",
                "-out", str(key))
        plain.unlink()
    return cert, key


class Server:
    """A running Stonegate whose output goes to a file read while it runs."""

    def __init__(self, work, config, *arguments):
        self.output = work / f"server-{time.monotonic_ns()}.log"
        self.log = self.output.open("w")
        self.process = subprocess.Popen([SERVER, "--config", str(config), *arguments],
                                        stdout=self.log, stderr=self.log)

    def text(self):
        return self.output.read_text()

    def wait_for(self, needle, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.text():
                return
            assert self.process.poll() is None, self.text()
            time.sleep(0.02)
        raise AssertionError(f"missing {needle!r} in output:\n{self.text()}")

    def ready(self, port, tls=False):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            assert self.process.poll() is None, self.text()
            try:
                fetch(port, "/healthz", tls=tls)
                return
            except (OSError, http.client.HTTPException):
                time.sleep(0.025)
        raise AssertionError(f"port {port} never answered:\n{self.text()}")

    def stop(self, sig=signal.SIGINT, timeout=10):
        if self.process.poll() is None:
            self.process.send_signal(sig)
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise AssertionError("Stonegate did not stop")
        self.log.close()
        assert code == 0, (code, self.text())


@contextlib.contextmanager
def running(work, config, *arguments):
    server = Server(work, config, *arguments)
    try:
        yield server
    finally:
        if server.process.poll() is None:
            server.stop()


def check_config(work, contents, expected=None, *arguments):
    config = work / "check.toml"
    config.write_text(contents)
    result = subprocess.run([SERVER, "--config", str(config), "--check", *arguments],
                            capture_output=True, text=True, timeout=10)
    output = result.stdout + result.stderr
    if expected is None:
        assert result.returncode == 0 and "Configuration OK" in output, output
    else:
        assert result.returncode == 1 and expected in output, (expected, output)


def wait_for_lines(path, count, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            lines = path.read_text().splitlines()
            if len(lines) >= count:
                return lines
        time.sleep(0.05)
    raise AssertionError(f"{path} has fewer than {count} lines")


def test_configuration_errors(work):
    base = '[defaults]\nroot = "public"\n'
    cases = [
        (base + '[defaults.headers]\n"content-type" = "text/plain"\n', "header name must be"),
        (base + '[defaults.headers]\n"x-ok" = "bad\\nvalue"\n', "header value is invalid"),
        (base + '[defaults.cache_control]\n"assets" = "max-age=1"\n', "cache_control pattern"),
        (base + '[defaults.error_pages]\n418 = "/teapot.html"\n', "error_pages status"),
        (base + '[defaults.error_pages]\n404 = "missing.html"\n', "document-root path"),
        (base + 'server_names = ["Example.com"]\n', "server-name must be"),
        (base + 'real_ip_header = "X-Forwarded-For"\n', "lowercase field name"),
        (base + 'access_log = "missing/access.log"\n', "access-log directory"),
        (base + '[defaults.compression]\ngzip_min_size = 10\ngzip_max_size = 5\n', "exceeds"),
        (base + '[runtime]\ngroup = "staff"\n', "group requires user"),
        (base + '[[server]]\nname = "a"\nserver_names = ["a.test"]\n'
                '[[server]]\nname = "b"\nserver_names = ["a.test"]\n', "repeats on shared listeners"),
        (base + '[[server]]\nname = "a"\nserver_names = ["a.test"]\n'
                '[[server]]\nname = "b"\nserver_names = ["b.test"]\nidle_timeout_ms = 5\n',
         "overlapping listening endpoints"),
    ]
    for contents, expected in cases:
        check_config(work, contents, expected)
    check_config(work, base + '[defaults.headers]\n"x-frame-options" = "DENY"\n'
                 '[defaults.cache_control]\n"/assets/" = "max-age=60"\n"*.html" = "no-cache"\n'
                 '[defaults.error_pages]\n404 = "/errors/404.html"\n')
    print("New setting validation: PASS")


def test_access_log(work):
    port, = free_ports(1)
    log = work / "logs" / "access.log"
    log.parent.mkdir()
    config = work / "access.toml"
    config.write_text(f'''[defaults]
root = "public"
access_log = "logs/access.log"
real_ip_header = "x-forwarded-for"
[defaults.http]
port = {port}
''')
    with running(work, config) as server:
        server.ready(port)
        fetch(port, "/index.html?q=1", {"Referer": "http://ref/", "User-Agent": "tester \"x\"",
                                        "X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
        fetch(port, "/missing")
        fetch(port, "/index.html", method="HEAD")
        lines = wait_for_lines(log, 4)
        first = next(line for line in lines if "/index.html?q=1" in line)
        assert first.startswith("203.0.113.7 - - ["), first
        assert '"GET /index.html?q=1 HTTP/1.1" 200 8 "http://ref/" "tester \\x22x\\x22" ' in first, first
        assert f'"127.0.0.1:{port}"' in first, first
        assert any('"GET /missing HTTP/1.1" 404 0' in line for line in lines), lines
        # Without the trusted field, the connection's address is logged.
        assert any(line.startswith('127.0.0.1 - - [') and '"HEAD /index.html HTTP/1.1" 200 0' in line
                   for line in lines), lines
        # Rotation: move the file away, then SIGHUP reopens the path.
        rotated = log.with_suffix(".1")
        log.rename(rotated)
        server.process.send_signal(signal.SIGHUP)
        server.wait_for("reopened access logs")
        fetch(port, "/after-rotation")
        assert any("/after-rotation" in line for line in wait_for_lines(log, 1)), log.read_text()
        assert "/after-rotation" not in rotated.read_text()
    print("Access log format, real client field, and SIGHUP reopen: PASS")


def test_compression(work):
    port, = free_ports(1)
    site = work / "compressed"
    site.mkdir()
    script = "function f() { return 1; }\n" * 400
    (site / "app.js").write_text(script)
    (site / "app.js.br").write_bytes(b"brotli-bytes")
    (site / "app.js.gz").write_bytes(gzip.compress(script.encode()))
    (site / "small.css").write_text("a{}\n")
    (site / "page.html").write_text("<p>hello</p>\n" * 300)
    (site / "image.png").write_bytes(b"\x89PNG" + b"\0" * 4000)
    config = work / "compression.toml"
    config.write_text(f'''[defaults]
root = "compressed"
[defaults.http]
port = {port}
[defaults.compression]
precompressed = true
gzip = true
gzip_min_size = 1024
''')
    with running(work, config) as server:
        server.ready(port)
        status, fields, body = fetch(port, "/app.js", {"Accept-Encoding": "gzip, br"})
        assert (status, fields.get("content-encoding"), body) == (200, "br", b"brotli-bytes"), fields
        assert fields["vary"] == "accept-encoding"
        assert fields["content-type"].startswith("text/javascript") or "javascript" in fields["content-type"]
        status, fields, body = fetch(port, "/app.js", {"Accept-Encoding": "br;q=0, gzip"})
        assert fields.get("content-encoding") == "gzip" and gzip.decompress(body).decode() == script
        status, fields, body = fetch(port, "/app.js", {"Accept-Encoding": "identity"})
        assert "content-encoding" not in fields and body.decode() == script, fields
        assert fields["vary"] == "accept-encoding"
        # On-the-fly gzip for a file without a precompressed copy.
        status, fields, body = fetch(port, "/page.html", {"Accept-Encoding": "gzip"})
        assert status == 200 and fields.get("content-encoding") == "gzip", fields
        assert gzip.decompress(body) == (site / "page.html").read_bytes()
        assert "content-length" not in fields or int(fields["content-length"]) == len(body)
        assert "accept-ranges" not in fields
        gzip_etag = fields["etag"]
        _, plain_fields, _ = fetch(port, "/page.html")
        assert plain_fields["etag"] != gzip_etag and "content-encoding" not in plain_fields
        status, _, body = fetch(port, "/page.html", {"Accept-Encoding": "gzip",
                                                     "If-None-Match": gzip_etag})
        assert status == 304 and body == b""
        status, fields, body = fetch(port, "/page.html", {"Accept-Encoding": "gzip",
                                                          "Range": "bytes=0-3"})
        assert status == 200 and gzip.decompress(body) == (site / "page.html").read_bytes()
        status, fields, _ = fetch(port, "/page.html", {"Accept-Encoding": "gzip"}, method="HEAD")
        assert status == 200 and fields.get("content-encoding") == "gzip"
        # Too small, or not a compressible type, is sent as is.
        _, fields, body = fetch(port, "/small.css", {"Accept-Encoding": "gzip"})
        assert "content-encoding" not in fields and body == b"a{}\n"
        _, fields, _ = fetch(port, "/image.png", {"Accept-Encoding": "gzip"})
        assert "content-encoding" not in fields and "vary" not in fields
        if CURL:
            # HTTP/2 is not configured here; curl decodes gzip on plain HTTP/1.1.
            result = subprocess.run([CURL, "--silent", "--fail", "--compressed",
                                     f"http://127.0.0.1:{port}/page.html"],
                                    capture_output=True, check=True)
            assert result.stdout == (site / "page.html").read_bytes()
    print("Precompressed br/gzip and on-the-fly gzip negotiation: PASS")


def test_virtual_hosts_and_policies(work):
    port, = free_ports(1)
    for name in ("alpha", "beta", "fallback"):
        root = work / name
        (root / "assets").mkdir(parents=True)
        (root / "index.html").write_text(f"{name}\n")
        (root / "assets" / "app.css").write_text("body{}\n")
    (work / "alpha" / "errors").mkdir()
    (work / "alpha" / "errors" / "404.html").write_text("<h1>alpha missing</h1>\n")
    config = work / "vhosts.toml"
    config.write_text(f'''[defaults]
bind = "127.0.0.1"
[defaults.http]
port = {port}
[defaults.headers]
"x-content-type-options" = "nosniff"

[[server]]
name = "alpha"
root = "alpha"
server_names = ["alpha.test", "www.alpha.test"]
[server.headers]
"strict-transport-security" = "max-age=60"
[server.cache_control]
"/assets/" = "public, max-age=31536000, immutable"
"*.html" = "no-cache"
[server.error_pages]
404 = "/errors/404.html"

[[server]]
name = "beta"
root = "beta"
server_names = ["*.beta.test"]

[[server]]
name = "fallback"
root = "fallback"
''')
    with running(work, config) as server:
        server.ready(port)
        server.wait_for("alpha,beta,fallback: HTTP/1.1 on 127.0.0.1")
        assert fetch(port, "/", {"Host": "alpha.test"})[2] == b"alpha\n"
        assert fetch(port, "/", {"Host": f"WWW.Alpha.Test:{port}"})[2] == b"alpha\n"
        assert fetch(port, "/", {"Host": "x.beta.test"})[2] == b"beta\n"
        assert fetch(port, "/", {"Host": "beta.test"})[2] == b"fallback\n"
        assert fetch(port, "/", {"Host": "other.test"})[2] == b"fallback\n"

        _, fields, _ = fetch(port, "/assets/app.css", {"Host": "alpha.test"})
        assert fields["cache-control"] == "public, max-age=31536000, immutable", fields
        assert fields["strict-transport-security"] == "max-age=60"
        assert fields["x-content-type-options"] == "nosniff"
        _, fields, _ = fetch(port, "/", {"Host": "alpha.test"})
        assert fields["cache-control"] == "no-cache", fields
        _, fields, _ = fetch(port, "/", {"Host": "beta.test"})
        assert "cache-control" not in fields and "strict-transport-security" not in fields
        assert fields["x-content-type-options"] == "nosniff"

        status, fields, body = fetch(port, "/nope", {"Host": "alpha.test"})
        assert (status, body) == (404, b"<h1>alpha missing</h1>\n"), (status, body)
        assert fields["content-type"].startswith("text/html")
        assert fields["strict-transport-security"] == "max-age=60"
        status, _, body = fetch(port, "/nope", {"Host": "beta.test"})
        assert (status, body) == (404, b"")
        status, fields, _ = fetch(port, "/", {"Host": "alpha.test"}, method="POST")
        assert status == 405 and fields["allow"] == "GET, HEAD, OPTIONS", fields
        status, fields, _ = fetch(port, "/", method="OPTIONS")
        assert status == 204 and fields["allow"] == "GET, HEAD, OPTIONS"
    print("Host-based virtual hosts, cache rules, headers, and error pages: PASS")


class Upstream(http.server.BaseHTTPRequestHandler):
    """A backend for the proxy tests; the path picks the response."""

    protocol_version = "HTTP/1.1"
    big = bytes(range(256)) * 8192  # 2 MiB

    def log_message(self, *arguments):
        pass

    def body(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return data
                data += self.rfile.read(size)
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("content-length", 0)))

    def answer(self, status, body, fields=()):
        self.send_response(status)
        for name, value in fields:
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionError, ValueError):
            self.close_connection = True

    def dispatch(self):
        path = self.path.split("?")[0]
        if path == "/slow":
            time.sleep(float(self.path.split("=")[1]))
        if path in ("/echo", "/slow", "/healthz"):
            received = self.body()
            lines = [f"{self.command} {self.path}"]
            lines += [f"{name.lower()}: {value}" for name, value in self.headers.items()]
            lines += ["", received.decode("latin-1")]
            self.answer(200, "\n".join(lines).encode("latin-1"),
                        [("content-type", "text/plain"), ("x-frame-options", "SAMEORIGIN"),
                         ("connection", "close, x-hop"), ("x-hop", "1")])
        elif path == "/big":
            self.answer(200, self.big, [("content-type", "application/octet-stream")])
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for part in (b"alpha ", b"beta " * 5000, b"gamma\n"):
                self.wfile.write(b"%x;ext=1\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\nx-trailer: 1\r\n\r\n")
        elif path == "/until-close":
            self.wfile.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nuntil close\n")
            self.close_connection = True
        elif path == "/interim":
            self.wfile.write(b"HTTP/1.1 103 Early Hints\r\nlink: </a.css>\r\n\r\n")
            self.answer(201, b"created\n")
        elif path == "/empty":
            self.send_response(204)
            self.end_headers()
        elif path == "/reset":
            self.send_response(200)
            self.send_header("content-length", str(len(self.big)))
            self.end_headers()
            self.wfile.write(self.big[:65536])
            self.wfile.flush()
            time.sleep(0.3)
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       struct.pack("ii", 1, 0))
            self.connection.close()
            self.close_connection = True
        elif path in ("/ws", "/ws-bad") and self.headers.get("upgrade", "").lower() == "websocket":
            self.websocket(path == "/ws-bad")
        elif path == "/ws-deny":
            self.answer(403, b"denied\n")
        elif path == "/garbage":
            self.wfile.write(b"NOT HTTP\r\n\r\n")
            self.close_connection = True
        else:
            self.answer(404, b"upstream missing\n")

    def websocket(self, bad_accept):
        """Echoes text frames with an "echo:" prefix after a greeting that
        reports what the proxy sent, then answers Close with Close."""
        key = self.headers["sec-websocket-key"]
        accept = "bad" if bad_accept else websocket_accept(key)
        offered = [item.strip() for item in self.headers.get("sec-websocket-protocol", "").split(",")]
        head = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n")
        if "chat" in offered:
            head += "Sec-WebSocket-Protocol: chat\r\n"
        seen = " ".join(self.headers.get(name, "-") for name in (
            "x-real-ip", "x-forwarded-proto", "origin", "sec-websocket-extensions"))
        # The greeting shares a write with the head, so it arrives behind it.
        self.wfile.write(head.encode() + b"\r\n" + ws_frame(1, f"hello {seen}".encode()))
        self.close_connection = True
        while True:
            opcode, payload = ws_read(self.rfile.read)
            if opcode == 8:
                self.wfile.write(ws_frame(8, payload))
                return
            self.wfile.write(ws_frame(1, b"echo:" + payload))

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = dispatch


def websocket_accept(key):
    digest = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    return base64.b64encode(digest).decode()


def ws_frame(opcode, payload, mask=False):
    """One final frame; clients mask, servers do not."""
    size = len(payload)
    bit = 0x80 if mask else 0
    head = bytes([0x80 | opcode])
    if size < 126:
        head += bytes([bit | size])
    elif size < 65536:
        head += bytes([bit | 126]) + struct.pack(">H", size)
    else:
        head += bytes([bit | 127]) + struct.pack(">Q", size)
    if mask:
        key = os.urandom(4)
        head += key
        payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return head + payload


def ws_read(read):
    """Reads one frame through read(count); returns (opcode, payload)."""
    first, second = read(2)
    size = second & 0x7F
    if size == 126:
        size, = struct.unpack(">H", read(2))
    elif size == 127:
        size, = struct.unpack(">Q", read(8))
    key = read(4) if second & 0x80 else None
    payload = read(size) if size else b""
    if key:
        payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return first & 0x0F, payload


def exact_reader(sock):
    pending = bytearray()

    def read(count):
        while len(pending) < count:
            data = sock.recv(65536)
            if not data:
                raise ConnectionError("closed")
            pending.extend(data)
        result = bytes(pending[:count])
        del pending[:count]
        return result

    def head():
        while b"\r\n\r\n" not in pending:
            data = sock.recv(65536)
            if not data:
                raise ConnectionError("closed")
            pending.extend(data)
        end = pending.index(b"\r\n\r\n") + 4
        text = bytes(pending[:end]).decode()
        del pending[:end]
        return text

    return read, head


def websocket_h1(port, host, path="/ws", tls=False):
    """Runs an HTTP/1.1 WebSocket exchange; returns (head, frames seen)."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock = ssl._create_unverified_context().wrap_socket(raw, server_hostname=host) if tls else raw
    with sock:
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: other, chat\r\n"
                      "Sec-WebSocket-Extensions: permessage-deflate\r\n"
                      "Origin: https://app.test\r\n\r\n").encode() +
                     ws_frame(1, b"first", mask=True))
        read, head = exact_reader(sock)
        response = head()
        if not response.startswith("HTTP/1.1 101 "):
            return response, []
        assert f"sec-websocket-accept: {websocket_accept(key)}\r\n" in response, response
        frames = [ws_read(read), ws_read(read)]
        large = bytes(range(256)) * 400
        sock.sendall(ws_frame(2, large, mask=True))
        frames.append(ws_read(read))
        assert frames[-1] == (1, b"echo:" + large), len(frames[-1][1])
        sock.sendall(ws_frame(8, struct.pack(">H", 1000), mask=True))
        frames.append(ws_read(read))
        assert sock.recv(1) == b"", "connection stays open after Close"
        return response, frames[:2] + frames[3:]


def websocket_h2(port, host):
    """An RFC 8441 WebSocket over HTTP/2; returns (status, fields, frames)."""
    context = ssl._create_unverified_context()
    context.set_alpn_protocols(["h2"])
    with context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                             server_hostname=host) as sock:
        connection = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        connection.initiate_connection()
        sock.sendall(connection.data_to_send())
        received = bytearray()
        state = {"fields": None, "ended": False}

        def pump(until):
            while not until():
                data = sock.recv(65536)
                if not data:
                    raise ConnectionError("closed")
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        state["fields"] = dict(event.headers)
                    elif isinstance(event, h2.events.DataReceived):
                        received.extend(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length, 1)
                    elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                        state["ended"] = True
                sock.sendall(connection.data_to_send())

        pump(lambda: connection.remote_settings.get(
            h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL, 0) == 1)
        connection.send_headers(1, [(":method", "CONNECT"), (":protocol", "websocket"),
                                    (":scheme", "https"), (":path", "/ws"),
                                    (":authority", host), ("sec-websocket-version", "13"),
                                    ("sec-websocket-protocol", "chat")])
        sock.sendall(connection.data_to_send())
        pump(lambda: state["fields"] is not None)
        fields = {name.decode(): value.decode() for name, value in state["fields"].items()}
        frames = []

        def frame():
            def complete():
                try:
                    ws_read(bytes_reader(bytes(received)))
                    return True
                except (IndexError, ValueError, struct.error):
                    return False
            pump(complete)
            consumed = bytes_reader(bytes(received))
            result = ws_read(consumed)
            del received[:consumed.offset]
            return result

        frames.append(frame())
        connection.send_data(1, ws_frame(1, b"over h2", mask=True))
        sock.sendall(connection.data_to_send())
        frames.append(frame())
        connection.send_data(1, ws_frame(8, struct.pack(">H", 1000), mask=True))
        sock.sendall(connection.data_to_send())
        frames.append(frame())
        return fields[":status"], fields, frames


class bytes_reader:
    """read(count) over a bytes value; ValueError when it runs short."""

    def __init__(self, data):
        self.data, self.offset = data, 0

    def __call__(self, count):
        if self.offset + count > len(self.data):
            raise ValueError("short")
        self.offset += count
        return self.data[self.offset - count:self.offset]


class Backend(http.server.ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True


def curl(*arguments):
    result = subprocess.run([CURL, "-sS", "--noproxy", "*", *arguments], capture_output=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_reverse_proxy(work):
    port, tls_port, unused = free_ports(3)
    backend = Backend(("127.0.0.1", 0), Upstream)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    upstream = backend.server_address[1]
    cert, key = make_certificate(work, "proxy")
    (work / "logs").mkdir(exist_ok=True)
    config = work / "proxy.toml"
    config.write_text(f'''[defaults]
access_log = "logs/proxy.log"
[defaults.http]
port = {port}
[defaults.tls]
port = {tls_port}
certificate = "{cert}"
private_key = "{key}"

[[server]]
name = "app"
server_names = ["app.test"]
[server.proxy]
upstream = "http://localhost:{upstream}/"
timeout_ms = 1000
max_request_body = 100000
[server.headers]
"x-frame-options" = "DENY"

[[server]]
name = "trusted"
server_names = ["trusted.test"]
real_ip_header = "x-forwarded-for"
[server.proxy]
upstream = "http://127.0.0.1:{upstream}"

[[server]]
name = "down"
server_names = ["down.test"]
[server.proxy]
upstream = "http://127.0.0.1:{unused}"

[[server]]
name = "static"
root = "public"
''')
    app = {"Host": "app.test"}
    with running(work, config) as server:
        server.ready(port)
        status, fields, body = fetch(port, "/echo?q=1", {
            **app, "X-Forwarded-For": "198.51.100.1", "Cookie": "a=1", "X-Custom": "yes",
            "Connection": "x-drop", "X-Drop": "1"})
        text = body.decode()
        assert status == 200 and text.startswith("GET /echo?q=1\n"), text
        for line in ("host: app.test", "x-forwarded-proto: http", "x-forwarded-host: app.test",
                     "cookie: a=1", "x-custom: yes", "connection: close"):
            assert line in text.splitlines(), (line, text)
        for line in ("x-forwarded-for: 127.0.0.1", "x-real-ip: 127.0.0.1"):
            assert line in text.splitlines(), (line, text)
        assert "198.51.100.1" not in text and "x-drop" not in text, text
        assert fields["x-frame-options"] == "DENY" and "x-hop" not in fields, fields
        assert fetch(port, "/", {"Host": "static.test"})[2] == b"website\n"
        # A malformed Host never reaches the application.
        for host in ("evil.com/x", "app.test?x", "a b"):
            assert fetch(port, "/echo", {"Host": host})[0] == 400, host
        assert fetch(port, "/echo", {"Host": "[::1]:8080"})[0] in (200, 404)
        # Behind a trusted proxy, its client list is extended and the first
        # entry becomes the real client.
        text = fetch(port, "/echo", {"Host": "trusted.test", "X-Forwarded-For": "198.51.100.1",
                                     "X-Real-IP": "203.0.113.9"})[2].decode()
        for line in ("x-forwarded-for: 198.51.100.1, 127.0.0.1", "x-real-ip: 198.51.100.1"):
            assert line in text.splitlines(), (line, text)

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("POST", "/echo", body=b"x" * 50000, headers=app)
        response = connection.getresponse()
        text = response.read().decode()
        assert response.status == 200 and "content-length: 50000" in text, text[:300]
        assert text.endswith("\n" + "x" * 50000), text[-100:]
        connection.request("PUT", "/echo", body=iter([b"one ", b"two"]), headers=app,
                           encode_chunked=True)
        response = connection.getresponse()
        text = response.read().decode()
        assert "transfer-encoding: chunked" in text and text.endswith("\none two"), text
        connection.close()

        status, fields, body = fetch(port, "/echo", app, method="HEAD")
        assert status == 200 and body == b"" and int(fields["content-length"]) > 0, fields
        status, fields, body = fetch(port, "/big", app)
        assert status == 200 and body == Upstream.big, (status, len(body))
        assert fields["content-length"] == str(len(Upstream.big)), fields
        status, fields, body = fetch(port, "/chunked", app)
        assert body == b"alpha " + b"beta " * 5000 + b"gamma\n", body[:40]
        assert "x-trailer" not in fields, fields
        assert fetch(port, "/until-close", app)[2] == b"until close\n"
        assert fetch(port, "/interim", app)[:3:2] == (201, b"created\n")
        assert fetch(port, "/empty", app)[0] == 204
        assert fetch(port, "/nothing", app)[:3:2] == (404, b"upstream missing\n")

        status, _, body = fetch(port, "/echo", app, method="POST")
        assert status == 200 and "content-length: 0" in body.decode(), body
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("POST", "/echo", body=b"x" * 100001, headers=app)
        assert connection.getresponse().status == 413
        connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("POST", "/echo", body=iter([b"x" * 60000] * 2), headers=app,
                           encode_chunked=True)
        assert connection.getresponse().status == 413
        connection.close()

        assert fetch(port, "/", {"Host": "down.test"})[0] == 502
        assert fetch(port, "/garbage", app)[0] == 502
        status, _, body = fetch(port, "/slow?s=2", app)
        assert status == 504 and body == b"504 gateway timeout\n", (status, body)

        # The upstream resets mid-body while Stonegate writes to the client.
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/reset", headers=app)
        response = connection.getresponse()
        try:
            data = response.read()
            assert len(data) < len(Upstream.big), len(data)
        except (http.client.IncompleteRead, ConnectionError):
            pass
        connection.close()
        assert fetch(port, "/echo", app)[0] == 200

        # HTTP/2 over TLS, including a request body without a length.
        resolve = f"app.test:{tls_port}:127.0.0.1"
        output = curl("--http2", "-k", "--resolve", resolve, f"https://app.test:{tls_port}/echo")
        assert b"x-forwarded-proto: https" in output and b"GET /echo" in output, output
        assert b"x-forwarded-for: 127.0.0.1" in output, output
        uploaded = subprocess.run(
            [CURL, "-sS", "--noproxy", "*", "--http2", "-k", "--resolve", resolve, "-T", "-",
             f"https://app.test:{tls_port}/echo"],
            input=b"streamed body", capture_output=True, timeout=10)
        assert uploaded.stdout.endswith(b"\nstreamed body"), uploaded
        assert b"transfer-encoding: chunked" in uploaded.stdout, uploaded.stdout
        output = curl("--http2", "-k", "--resolve", resolve, f"https://app.test:{tls_port}/big")
        assert output == Upstream.big, len(output)

        # Requests in flight at once each hold a proxy exchange.
        results = []
        def slow():
            results.append(fetch(port, "/slow?s=0.3", app)[0])
        workers = [threading.Thread(target=slow) for _ in range(64)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        assert results == [200] * 64, results

        lines = wait_for_lines(work / "logs" / "proxy.log", 20)
        assert any('"GET /big HTTP/1.1" 200 2097152' in line for line in lines), lines
        assert any('"GET / HTTP/1.1" 502' in line for line in lines), lines
        assert all(line.startswith(("127.0.0.1 ", "198.51.100.1 ")) for line in lines), lines
    backend.shutdown()
    check_config(work, '[defaults]\n[defaults.proxy]\nupstream = "http://example.com"\n',
                 "proxy upstream must be")
    check_config(work, '[defaults]\n[defaults.proxy]\nupstream = "http://[::1]:8000"\n')
    check_config(work, '[defaults]\n[defaults.proxy]\nupstream = "http://127.0.0.1:0"\n',
                 "proxy upstream port")
    print("Reverse proxy forwarding, framing, limits, failures, and HTTP/2: PASS")


def test_websocket_proxy(work):
    port, tls_port = free_ports(2)
    backend = Backend(("127.0.0.1", 0), Upstream)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    cert, key = make_certificate(work, "websocket")
    config = work / "websocket.toml"
    config.write_text(f'''[defaults]
access_log = "logs/websocket.log"
[defaults.http]
port = {port}
[defaults.tls]
port = {tls_port}
certificate = "{cert}"
private_key = "{key}"

[[server]]
name = "app"
server_names = ["app.test"]
[server.proxy]
upstream = "http://127.0.0.1:{backend.server_address[1]}"
timeout_ms = 1000

[[server]]
name = "static"
root = "public"
''')
    with running(work, config) as server:
        server.ready(port)
        for tls in (False, True):
            head, frames = websocket_h1(tls_port if tls else port, "app.test", tls=tls)
            assert head.startswith("HTTP/1.1 101 "), head
            assert "sec-websocket-protocol: chat" in head.lower(), head
            scheme = "https" if tls else "http"
            # Extensions are not negotiated through the proxy.
            assert frames == [(1, f"hello 127.0.0.1 {scheme} https://app.test -".encode()),
                              (1, b"echo:first"), (8, struct.pack(">H", 1000))], frames
        head, _ = websocket_h1(port, "app.test", "/ws-deny")
        assert head.startswith("HTTP/1.1 403 "), head
        head, _ = websocket_h1(port, "app.test", "/ws-bad")
        assert head.startswith("HTTP/1.1 502 "), head
        # Ordinary requests still work on the same server.
        assert fetch(port, "/echo", {"Host": "app.test"})[0] == 200
        note = ""
        if h2:
            status, fields, frames = websocket_h2(tls_port, "app.test")
            assert status == "200" and fields.get("sec-websocket-protocol") == "chat", fields
            assert frames == [(1, b"hello 127.0.0.1 https - -"), (1, b"echo:over h2"),
                              (8, struct.pack(">H", 1000))], frames
        else:
            note = " (HTTP/2 check skipped: Python h2 missing)"
        lines = wait_for_lines(work / "logs" / "websocket.log", 5)
        assert any('"GET /ws HTTP/1.1" 101' in line for line in lines), lines
    backend.shutdown()
    print(f"WebSocket proxying over HTTP/1.1, TLS, and HTTP/2: PASS{note}")


def test_acme_challenge(work):
    port, tls_port = free_ports(2)
    backend = Backend(("127.0.0.1", 0), Upstream)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    cert, key = make_certificate(work, "acme")
    webroot = work / "acme"
    challenges = webroot / ".well-known" / "acme-challenge"
    challenges.mkdir(parents=True)
    (challenges / "tok_en-1").write_text("tok_en-1.thumbprint")
    (challenges / "link").symlink_to(challenges / "tok_en-1")
    (challenges / "folder").mkdir()
    config = work / "acme.toml"
    config.write_text(f'''[defaults]
acme_webroot = "acme"
[defaults.http]
port = {port}
mode = "redirect"
redirect_host = "app.test"
[defaults.tls]
port = {tls_port}
certificate = "{cert}"
private_key = "{key}"

[[server]]
name = "app"
server_names = ["app.test"]
[server.proxy]
upstream = "http://127.0.0.1:{backend.server_address[1]}"

[[server]]
name = "plain"
server_names = ["plain.test"]
root = "public"
acme_webroot = ""

[[server]]
name = "static"
root = "public"
''')
    path = "/.well-known/acme-challenge/"
    app = {"Host": "app.test"}
    with running(work, config) as server:
        server.ready(tls_port, tls=True)
        # Plain HTTP answers the challenge instead of redirecting, for the
        # proxied site and for the fallback static site.
        for host in ("app.test", "static.test"):
            status, fields, body = fetch(port, path + "tok_en-1", {"Host": host})
            assert (status, body) == (200, b"tok_en-1.thumbprint"), (host, status, body)
            assert fields["content-type"] == "text/plain" and fields["cache-control"] == "no-store"
        status, _, body = fetch(port, path + "tok_en-1", app, method="HEAD")
        assert (status, body) == (200, b""), status
        for token in ("missing", "link", "folder", "..%2Ftok_en-1", "a.b", ""):
            status, fields, _ = fetch(port, path + token, app)
            assert status == 404 and "location" not in fields, (token, status)
        status, fields, _ = fetch(port, "/elsewhere", app)
        assert status == 308 and fields["location"] == f"https://app.test:{tls_port}/elsewhere"
        assert fetch(port, path + "tok_en-1", app, method="POST")[0] == 308
        # A server that clears the setting keeps redirecting challenges.
        assert fetch(port, path + "tok_en-1", {"Host": "plain.test"})[0] == 308
        # Over HTTPS the proxied site still answers challenges itself.
        status, _, body = fetch(tls_port, path + "tok_en-1", app, tls=True)
        assert (status, body) == (200, b"tok_en-1.thumbprint"), (status, body)
        assert fetch(tls_port, "/echo", app, tls=True)[2].startswith(b"GET /echo")
        # certbot may remove the challenge directories between runs.
        shutil.rmtree(webroot / ".well-known")
        assert fetch(port, path + "tok_en-1", app)[0] == 404
        challenges.mkdir(parents=True)
        (challenges / "second").write_text("second.thumbprint")
        assert fetch(port, path + "second", app)[2] == b"second.thumbprint"
    backend.shutdown()
    check_config(work, '[defaults]\nroot = "public"\nacme_webroot = "missing"\n',
                 "acme-webroot must name an existing directory")
    print("ACME HTTP-01 challenges before redirects and proxying: PASS")


def test_redirect_keeps_named_host(work):
    port, tls_port = free_ports(2)
    cert, key = make_certificate(work, "redirect")
    config = work / "redirect.toml"
    config.write_text(f'''[defaults.http]
port = {port}
mode = "redirect"
redirect_host = "main.test"
[defaults.tls]
port = {tls_port}
certificate = "{cert}"
private_key = "{key}"

[[server]]
name = "main"
root = "public"
server_names = ["main.test"]

[[server]]
name = "apps"
root = "public"
server_names = ["*.apps.test"]
''')
    with running(work, config) as server:
        server.ready(tls_port, tls=True)
        cases = [
            ("main.test", f"https://main.test:{tls_port}/a?b=1"),
            (f"Movies.Apps.Test.:{port}", f"https://movies.apps.test:{tls_port}/a?b=1"),
            ("apps.test", f"https://main.test:{tls_port}/a?b=1"),
            ("evil.test", f"https://main.test:{tls_port}/a?b=1"),
            ("127.0.0.1", f"https://main.test:{tls_port}/a?b=1"),
        ]
        for host, location in cases:
            status, fields, _ = fetch(port, "/a?b=1", {"Host": host})
            assert (status, fields["location"]) == (308, location), (host, fields)
        # A malformed Host that ends like a server name must not choose the
        # redirect target (open redirect); it is refused.
        for host in ("evil.com/x.apps.test", "evil.com?.apps.test", "evil.com#.apps.test",
                     "evil.com\\x.apps.test", "user@x.apps.test", "x.apps.test:", "x.apps.test:1:2"):
            status, fields, _ = fetch(port, "/a", {"Host": host})
            assert status == 400 and "location" not in fields, (host, status, fields)
    print("HTTP redirects keep a configured host name: PASS")


def test_certificate_reload(work):
    tls_port, h3_port = free_ports(2)
    cert, key = work / "live-cert.pem", work / "live-key.pem"
    first_cert, first_key = make_certificate(work, "first")
    second_cert, second_key = make_certificate(work, "second")
    shutil.copyfile(first_cert, cert)
    shutil.copyfile(first_key, key)
    config = work / "reload.toml"
    config.write_text(f'''[defaults]
root = "public"
[defaults.http]
mode = "off"
[defaults.tls]
port = {tls_port}
certificate = "live-cert.pem"
private_key = "live-key.pem"
[defaults.http3]
port = {h3_port}
''')
    with running(work, config) as server:
        server.ready(tls_port, tls=True)
        assert peer_certificate(tls_port) == certificate_der(first_cert)
        kept = http.client.HTTPSConnection("127.0.0.1", tls_port, timeout=5,
                                           context=ssl._create_unverified_context())
        assert fetch(tls_port, "/", connection=kept)[0] == 200

        shutil.copyfile(second_cert, work / "next-cert.pem")
        shutil.copyfile(second_key, work / "next-key.pem")
        os.replace(work / "next-key.pem", key)
        os.replace(work / "next-cert.pem", cert)
        server.process.send_signal(signal.SIGHUP)
        server.wait_for("reloaded certificates")
        deadline = time.monotonic() + 3
        while peer_certificate(tls_port) != certificate_der(second_cert):
            assert time.monotonic() < deadline, "new connections still get the old certificate"
            time.sleep(0.02)
        # A connection opened before the reload keeps working.
        assert fetch(tls_port, "/", connection=kept)[0] == 200
        kept.close()
        if CURL_H3:
            result = subprocess.run([CURL, "--http3-only", "--silent", "--show-error", "--fail",
                                     "--max-time", "5", "--cacert", str(second_cert), "--resolve",
                                     f"localhost:{h3_port}:127.0.0.1", f"https://localhost:{h3_port}/"],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0 and result.stdout == b"website\n", result.stderr

        # A broken key leaves the working certificate in place.
        key.write_text("not a key\n")
        server.process.send_signal(signal.SIGHUP)
        server.wait_for("reload failed; keeping the old certificates")
        assert peer_certificate(tls_port) == certificate_der(second_cert)
        assert fetch(tls_port, "/", tls=True)[0] == 200
    print("SIGHUP certificate reload, kept connections, and failed reload: PASS"
          + ("" if CURL_H3 else " (HTTP/3 check skipped: curl lacks HTTP3)"))


def test_draining_shutdown(work):
    port, = free_ports(1)
    big = work / "public" / "big.bin"
    with big.open("wb") as output:
        block = bytes(range(256)) * 4096
        for _ in range(64):
            output.write(block)
    size = big.stat().st_size
    config = work / "drain.toml"
    config.write_text(f'''[runtime]
shutdown_seconds = 20
[defaults]
root = "public"
[defaults.http]
port = {port}
''')
    server = Server(work, config)
    try:
        server.ready(port)
        client = socket.socket()
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        client.connect(("127.0.0.1", port))
        client.sendall(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
        received = b""
        while b"\r\n\r\n" not in received:
            received += client.recv(65536)
        head, body = received.split(b"\r\n\r\n", 1)
        assert b"200" in head.split(b"\r\n")[0], head
        total = len(body)
        server.process.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        # The listener is closed while the transfer continues.
        with socket.socket() as late:
            late.settimeout(1)
            try:
                late.connect(("127.0.0.1", port))
                late.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                refused = late.recv(1) == b""
            except OSError:
                refused = True
        assert refused, "a new connection was served after SIGTERM"
        while total < size:
            chunk = client.recv(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            time.sleep(0.005)
        client.close()
        assert total == size, f"transfer cut at {total} of {size} bytes"
        server.stop(timeout=25)
    finally:
        if server.process.poll() is None:
            server.process.kill()
    big.unlink()
    print("SIGTERM drains an in-flight download before exiting: PASS")


def test_encrypted_http3_key(work):
    tls_port, h3_port = free_ports(2)
    cert, key = make_certificate(work, "encrypted", password="PRIVATE_SENTINEL_739")
    assert "ENCRYPTED" in key.read_text()
    config = work / "encrypted.toml"
    config.write_text(f'''[defaults]
root = "public"
[defaults.http]
mode = "off"
[defaults.tls]
port = {tls_port}
certificate = "{cert.name}"
private_key = "{key.name}"
key_password = "PRIVATE_SENTINEL_739"
[defaults.http3]
port = {h3_port}
''')
    check_config(work, config.read_text())
    check_config(work, config.read_text().replace("PRIVATE_SENTINEL_739", "wrong"), "server")
    with running(work, config) as server:
        server.ready(tls_port, tls=True)
        if CURL_H3:
            result = subprocess.run([CURL, "--http3-only", "--silent", "--show-error", "--fail",
                                     "--max-time", "5", "--cacert", str(cert), "--resolve",
                                     f"localhost:{h3_port}:127.0.0.1", f"https://localhost:{h3_port}/"],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0 and result.stdout == b"website\n", result.stderr
        assert "PRIVATE_SENTINEL_739" not in server.text()
    print("Encrypted private key on TLS and HTTP/3: PASS"
          + ("" if CURL_H3 else " (HTTP/3 request skipped: curl lacks HTTP3)"))


def test_account_switch(work):
    base = '[defaults]\nroot = "public"\n'
    if os.geteuid() != 0:
        other = "nobody" if getpass.getuser() != "nobody" else "daemon"
        check_config(work, base, "needs root", "--user", other)
        check_config(work, base, None, "--user", getpass.getuser())
        print("Account switch checks (not root; switching itself untested): PASS")
        return
    port, = free_ports(1)
    config = work / "account.toml"
    config.write_text(base + f'[defaults.http]\nport = {port}\n[runtime]\nuser = "nobody"\n')
    (work / "public").chmod(0o755)
    work.chmod(0o755)
    with running(work, config) as server:
        server.ready(port)
        status = pathlib.Path(f"/proc/{server.process.pid}/status")
        if status.exists():
            uid_line = next(line for line in status.read_text().splitlines()
                            if line.startswith("Uid:"))
            assert all(value != "0" for value in uid_line.split()[1:]), uid_line
    print("Switch to nobody after binding as root: PASS")


def main(work):
    (work / "public").mkdir()
    (work / "public" / "index.html").write_text("website\n")
    test_configuration_errors(work)
    test_access_log(work)
    test_compression(work)
    test_virtual_hosts_and_policies(work)
    test_reverse_proxy(work)
    test_websocket_proxy(work)
    test_redirect_keeps_named_host(work)
    test_acme_challenge(work)
    test_certificate_reload(work)
    test_draining_shutdown(work)
    test_encrypted_http3_key(work)
    test_account_switch(work)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="stonegate-features-") as directory:
        main(pathlib.Path(directory))
