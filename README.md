# Stonegate

A static file server and reverse proxy for HTTP/1.1, TLS HTTP/1.1 and HTTP/2,
and HTTP/3, built on the [eventloop](https://github.com/ArdaKemal/eventloop)
C++23 coroutine library. It serves several sites by host name, forwards sites
to local HTTP/1.1 applications, writes access logs, compresses
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
3. a download of `EVENTLOOP_GIT_TAG` (default `v0.2.0`, the release
   Stonegate is tested with) from `EVENTLOOP_GIT_REPOSITORY`.

The reverse proxy needs eventloop 0.2 or newer (`tcp_stream_hold`); an
installed package older than 0.2 is ignored.

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
  (exact names, then `*.domain` wildcards, then a default). HTTP-to-HTTPS
  redirects keep a configured host name. One certificate
  per TLS listener; use a SAN or wildcard certificate across names.
- **Reverse proxy**: a server with `[server.proxy] upstream =
  "http://127.0.0.1:8096"` forwards every request to that HTTP/1.1
  application, such as Jellyfin or Gitea, and streams the response back,
  over every listener protocol. Bodies stream both ways; WebSockets pass
  through from HTTP/1.1 Upgrade, HTTP/2, or HTTP/3 clients; timeouts,
  request body limits, and 502/504 answers are per server.
- **ACME challenges**: `acme_webroot` answers Let's Encrypt HTTP-01
  challenges from a certbot webroot before redirects and proxying, so every
  site, proxied ones included, can get and renew certificates.
- **Access logs**: Combined Log Format plus host and duration, per server or
  shared, written by a background thread with a bounded buffer.
  Clients are logged by address, or by a trusted proxy's field with
  `real_ip_header`.
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

Let's Encrypt certificates for every site, proxied ones included, come from
a certbot webroot. With `acme_webroot = "/var/www/acme"` in `[defaults]`:

```sh
certbot certonly --webroot -w /var/www/acme \
  -d example.com -d movies.example.com -d git.example.com \
  --deploy-hook "systemctl reload stonegate"
```

Redirect mode needs a certificate to start, so the first issuance runs with
`http.mode = "serve"` (or without TLS settings); afterwards enable TLS and
the redirect. Renewals (`certbot renew`) work while HTTP redirects, and the
deploy hook's reload picks up the new certificate. certbot keeps private
keys readable only to root, so make them readable to Stonegate's account
(for example through a group) for reloads after it drops root.

## Limits

- No SNI: one certificate per TLS listener, as eventloop's `https_server` and
  `http3_server` take one each.
- Proxied applications receive the client address in `X-Forwarded-For` and
  `X-Real-IP`; they must trust Stonegate's address as a proxy to use it.
- The proxy opens one upstream connection per request and speaks plain
  HTTP/1.1 to numeric addresses only.
- A reload closes HTTP/3 connections (clients reconnect) and may reset a TCP
  connection still waiting in the old listener's backlog. Other settings
  need a restart.
- Requests rejected inside eventloop before routing (malformed heads,
  oversized bodies, timeouts) get eventloop's empty error responses and are
  not logged.
- HTTP/2 is TLS only. HTTP/3 has no dynamic QPACK, push, or WebTransport.
  No CGI or custom routes.
- Both projects have libFuzzer harnesses for their parsers (`fuzz/`). So far
  they have had short local runs (10 to 25 minutes per harness, about 600
  million inputs in all), which found one bug, now fixed. Longer or
  continuous fuzzing is still to come.

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
virtual hosts, policies and error pages, HTTPS redirects, ACME challenges,
the reverse proxy (framing, limits, upstream failures and resets, client
addresses, WebSockets, HTTP/2), certificate reload (including a failed
one), draining shutdown, encrypted HTTP/3 keys, and account checks.
They need Python 3, the OpenSSL CLI, and curl. HTTP/3 checks use curl when
it has HTTP/3 and otherwise eventloop's `http3_client`, which is built with
the tests when eventloop is built from source.
