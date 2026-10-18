#!/usr/bin/env python3
"""Exercise access logs, compression, virtual hosts, response policies,
certificate reload, draining shutdown, encrypted HTTP/3 keys, and account
switching through the Stonegate executable."""
import contextlib
import getpass
import gzip
import http.client
import os
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

SERVER = str(pathlib.Path(sys.argv[1]).resolve())
CURL = shutil.which("curl")
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
        assert any(line.startswith('- - - [') and '"HEAD /index.html HTTP/1.1" 200 0' in line
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
    test_certificate_reload(work)
    test_draining_shutdown(work)
    test_encrypted_http3_key(work)
    test_account_switch(work)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="stonegate-features-") as directory:
        main(pathlib.Path(directory))
