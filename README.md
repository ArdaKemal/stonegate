# Stonegate

A static file server for HTTP/1.1, TLS HTTP/1.1 and HTTP/2, and HTTP/3, built
on the [eventloop](https://github.com/ArdaKemal/eventloop) C++23 coroutine
library. It serves several sites by host name, writes access logs, compresses
text, applies cache and header policies, reloads certificates without a
restart, drains requests on shutdown, and drops root after binding.

## Build

Stonegate needs a C++23 compiler, CMake 3.20+, OpenSSL 3.5+, and threads, and
runs on Linux, macOS, and other POSIX systems. zlib enables on-the-fly gzip.
CMake finds eventloop in this order:

1. `-DEVENTLOOP_SOURCE_DIR=/path/to/eventloop`, a source checkout built with
   Stonegate (without eventloop's examples and tests);
2. an installed package exporting `eventloop::eventloop`, found through
   `CMAKE_PREFIX_PATH`;
3. a download of `EVENTLOOP_GIT_TAG` (default `v0.1.0`, the release
   Stonegate is tested with) from `EVENTLOOP_GIT_REPOSITORY`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run

```sh
mkdir -p /tmp/site && printf 'hello\n' > /tmp/site/index.html
./build/stonegate --root /tmp/site --http-port 8080
curl http://127.0.0.1:8080/
```

With a certificate, redirect plain HTTP to TLS and add HTTP/3:

```sh
./build/stonegate --root /tmp/site \
  --certificate cert.pem --private-key key.pem \
  --http-mode redirect --redirect-host localhost \
  --http-port 8080 --https-port 8443 --http3-port 8443
curl --http3-only --cacert cert.pem https://localhost:8443/
```

HTTPS file responses carry `Alt-Svc: h3=":8443"; ma=86400` so browsers move to
HTTP/3. `stonegate --help` lists every option; most deployments use a file:

```sh
cp stonegate.toml.example stonegate.toml && mkdir public
./build/stonegate --config stonegate.toml --check
./build/stonegate --config stonegate.toml
```

## Features

The [configuration reference](docs/configuration.md) gives every setting,
bound, and rule.

- **Virtual hosts**: servers on the same ports are picked by `server_names`
  (exact names, then `*.domain` wildcards, then a default). One certificate
  per TLS listener; use a SAN or wildcard certificate across names.
- **Access logs**: Combined Log Format plus host and duration, per server or
  shared, written by a background thread with a bounded buffer.
  `real_ip_header` logs the client address from a trusted proxy's field.
- **Compression**: precompressed `FILE.br`/`FILE.gz`, and gzip while sending
  for text, JSON, XML, JavaScript, and SVG, with `Vary` and separate ETags.
- **Policies**: `Cache-Control` by path prefix or extension, extra headers
  such as HSTS on every response, and custom pages for 400, 403, 404, 405,
  414, and 500.
- **Static files**: validators, single ranges, HEAD, `index.html`, bounded
  directory listings, and traversal that refuses symbolic links and `..`.
- **Operations**: SIGHUP reloads certificates and reopens logs; SIGTERM stops
  accepting and lets in-flight requests finish for `shutdown_seconds`;
  `user`/`group` drop root once listeners are open; encrypted keys work for
  TLS and HTTP/3; several worker threads can share the listeners.

## Deploying

A systemd unit that starts as root, binds port 443, and drops to `www-data`:

```ini
[Service]
ExecStart=/usr/local/bin/stonegate --config /etc/stonegate/stonegate.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
```

with `[runtime] user = "www-data"` and `shutdown_seconds` below
`TimeoutStopSec`. To never run as root, set `User=www-data` and
`AmbientCapabilities=CAP_NET_BIND_SERVICE` instead and leave `user` unset.
Certificate renewal hooks and logrotate's `postrotate` run
`systemctl reload stonegate`. Keep certificate files readable to the account
Stonegate runs as, since reloads happen after the switch.

## Limits

- No SNI: one certificate per TLS listener, as eventloop's `https_server` and
  `http3_server` take one each.
- The client address is not available from eventloop's request API; logs
  show `-` unless `real_ip_header` is set behind a proxy.
- A reload closes HTTP/3 connections (clients reconnect) and may reset a TCP
  connection still waiting in the old listener's backlog. Other settings
  need a restart.
- Requests rejected inside eventloop before routing (malformed heads,
  oversized bodies, timeouts) get eventloop's empty error responses and are
  not logged.
- HTTP/2 is TLS only. HTTP/3 has no dynamic QPACK, push, or WebTransport.
  No uploads, proxying, CGI, or custom routes.
- The parsers are eventloop's; neither project is fuzzed yet. Put a proxy or
  CDN in front for hostile traffic until it is.

## Tests

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

`stonegate_smoke` covers redirects, TLS, HTTP/2 and HTTP/3, validators,
ranges, listings, traversal, and CLI/config equivalence (HTTP/2 and HTTP/3
checks need a curl with them). `stonegate_configuration` covers the schema,
includes, inheritance, timeouts, workers, and startup cleanup.
`stonegate_features` covers access logs and their rotation, compression,
virtual hosts, policies and error pages, certificate reload (including a
failed one), draining shutdown, encrypted HTTP/3 keys, and account checks.
They need Python 3, the OpenSSL CLI, and curl.
