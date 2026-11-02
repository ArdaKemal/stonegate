# Stonegate configuration

Stonegate reads TOML with its own [TOML 1.1 parser](toml.md). CLI-only
invocations work without a file. A typical deployment is several sites behind
one set of ports, picked by host name, some static and some forwarded to
local applications, with common policy in `[defaults]` and sites split into
included files.

## Structure and inheritance

The main file accepts `include` (an array of exact file paths), `[runtime]`,
`[defaults]`, and `[[server]]` tables. Included files accept only `include`
and `[[server]]`. Includes are visited in array order, depth first, before
servers in the including file. Globs and environment substitution are absent.
The main file's defaults apply to every server regardless of include order.
Each server copies those defaults, then overrides only its explicit fields;
nested protocol tables merge by field, `headers`, `cache_control`, and
`error_pages` merge by key, and `server_names` replaces the inherited list.
Server names are unique, optional, and otherwise generated as `server-1`,
`server-2`, etc.; they label servers in output and errors.

If no server tables exist anywhere, defaults form one implicit server.
All paths resolve beside the file defining that value; inherited paths retain
that resolution. CLI paths resolve from the working directory. CLI settings
apply after the complete configuration, in written order, regardless of
`--config` position. With multiple servers, server options require
`--server NAME`; this selects one server for all CLI overrides. `--server`
does not prevent other servers from running. `--shutdown-seconds`,
`--workers`, `--worker-mode`, `--user`, `--group`, and `--check` are global.

## Schema

Unknown keys/tables, duplicate TOML keys, wrong types, invalid values, missing
roots/credentials, duplicate names, and overlapping endpoints fail startup.
Strings must exclude NUL. Diagnostics omit setting values and source lines;
config filenames and setting/server names identify the error. Syntax errors
give file, line, column and error category; schema errors give file and dotted
setting path. Cross-field validation errors identify the merged server.

Fields below are allowed under both `defaults` and each `server`.

| Field | Type | Default / bounds |
| --- | --- | --- |
| `root` | string path | Existing directory; required unless `proxy.upstream` is set |
| `bind` | string | `127.0.0.1`; numeric IPv4/IPv6, optional numeric IPv6 scope |
| `server_names` | array of strings | Empty (any host); up to 16 lowercase names or `*.domain` |
| `directory_listing` | boolean | `false` |
| `reuse_port` | boolean | `false`; plain HTTP listeners (TLS and HTTP/3 always reuse) |
| `header_timeout_ms` | integer | 30000; 0..3600000, 0 disables; TCP only |
| `idle_timeout_ms` | integer | 60000; 0..3600000, 0 disables; TCP only |
| `access_log` | string path | Empty (off); `-` is standard output |
| `real_ip_header` | string | Empty; lowercase field such as `x-forwarded-for` |
| `http.mode` | string | `serve`; `serve`, `redirect`, `off` |
| `http.port` | integer | 8080; 1..65535 |
| `http.redirect_host` | string | `localhost`; HTTPS redirect host for unnamed hosts |
| `tls.port` | integer | 8443; 0..65535, 0 disables TCP TLS |
| `tls.certificate` | string path | PEM certificate chain; empty clears inheritance |
| `tls.private_key` | string path | PEM key; empty clears inheritance |
| `tls.key_password` | string | Empty; protect config file permissions |
| `tls.http2` | boolean | `true`; ALPN advertisement |
| `http3.port` | integer | 0 (off); 0..65535, UDP; advertised in HTTPS `Alt-Svc` |
| `http3.connections` | integer | 8; 1..256 per server |
| `http3.requests` | integer | 0 (ten per connection); 0..8192 per server |
| `http3.max_datagram` | integer | 8192; 1200..8192 bytes, reached by path MTU probing |
| `compression.precompressed` | boolean | `false`; serve `FILE.br` or `FILE.gz` |
| `compression.gzip` | boolean | `false`; gzip while sending (needs zlib) |
| `compression.gzip_min_size` | integer | 1024; 0..1 GiB |
| `compression.gzip_max_size` | integer | 8388608; 0..1 GiB, at least the minimum |
| `headers` | table of strings | Up to 32 fields added to every response |
| `cache_control` | table of strings | Up to 64 `"/prefix"` or `"*.ext"` rules |
| `error_pages` | table of strings | Status (400, 403, 404, 405, 414, 500) to a root path |
| `proxy.upstream` | string | Empty (serve files); `http://ADDRESS[:PORT]`, port 80 by default |
| `proxy.timeout_ms` | integer | 60000; 1..3600000 |
| `proxy.max_request_body` | integer | 1048576; 0..1 TiB bytes |

`server.name` is a nonempty string, at most 64 ASCII letters, digits, `_`, `-`
or `.`. `[runtime]` accepts `shutdown_seconds` (integer, default 5, 0..3600),
`workers` (integer, default 1, 1..256), `worker_mode` (`auto`, `reuse_port`,
or `handoff`; default `auto`), and `user` and `group` (account names; `group`
needs `user`). TLS credentials must be paired. Redirect requires TCP TLS;
HTTP-off requires an enabled TLS or HTTP/3 listener. HTTP/3 requires
credentials; an encrypted key works with `key_password`. TCP HTTP and TLS
cannot share an endpoint; TCP and UDP may share a port.

## Virtual hosts

Servers whose endpoints overlap (the same transport and port on the same or a
wildcard address; IPv6 is v6-only) must share every listener setting: `bind`,
every port and `http.mode`, the TLS files and password, `tls.http2`, the
`http3` capacities, `reuse_port`, `redirect_host`, and both timeouts.
Anything else is an overlapping-endpoint error. Servers sharing listeners
pick requests by the request host (`Host`, or `:authority` on HTTP/2 and
HTTP/3), compared without case, port, or a trailing dot: an exact
`server_names` entry first, then the longest matching `*.domain` wildcard
(which matches subdomains, not the domain itself), then the one server
without `server_names`, or else the first server. A name appears at most once
among servers sharing listeners, and at most one of them omits
`server_names`.

TLS certificates are not selected by SNI: servers sharing a TLS listener use
its one certificate, so it must cover every name (a SAN or wildcard
certificate). Root, listing, compression, logging, and policy settings stay
per server.

## Reverse proxy

A server with `proxy.upstream` forwards every request it is picked for,
`/healthz` included, to that HTTP/1.1 address instead of serving files; its
`root`, listing, compression, cache, and error-page settings are unused.
`headers`, `access_log`, and `real_ip_header` still apply. The address is a
numeric IPv4 address, a bracketed IPv6 address, or `localhost` (127.0.0.1),
with an optional trailing `/`; there is no DNS lookup and no TLS to the
upstream. An empty value clears an inherited upstream. A plain listener
with `http.mode = "redirect"` still redirects instead of forwarding.

```toml
[[server]]
name = "movies"
server_names = ["movies.example.com"]
[server.proxy]
upstream = "http://127.0.0.1:8096"
max_request_body = 104_857_600
```

Each request opens a new upstream connection and sends `connection: close`.
The request keeps its method, path, query, `Host`, and fields, except
connection-specific ones (`connection` and the fields it names, `keep-alive`,
`proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`,
`http2-settings`) and `expect`. Split HTTP/2 and HTTP/3 cookies are joined
into one field. Stonegate sets `x-forwarded-proto` (`http`, or `https` on
TLS and HTTP/3) and `x-forwarded-host`, replacing client values. Client
`x-forwarded-for`, `forwarded`, and `x-real-ip` fields are removed unless
`real_ip_header` is set, which marks Stonegate as running behind a trusted
proxy. Stonegate does not know the client address, so it adds none.

A body with a declared length is forwarded with that length; one without
(HTTP/1.1 chunked, or HTTP/2 and HTTP/3 without `content-length`) is
forwarded chunked. POST, PUT, and PATCH without a body send
`content-length: 0`. A body above `proxy.max_request_body` answers 413
before or while it is forwarded. The listeners accept bodies up to the
largest limit among the servers sharing them, and at least 1 MiB.

The upstream response may use `content-length`, chunked coding (extensions
and trailers are dropped), or end at connection close; 1xx responses are
skipped. Its status and fields reach the client, minus connection-specific
fields, and a `content-length` is kept so clients see the size. A site
`headers` field replaces an upstream field of the same name. The body
streams through a 32 KiB buffer as it arrives.

`proxy.timeout_ms` bounds connecting, each upstream read and write, and each
request body read. An upstream that refuses the connection, closes early, or
sends a malformed head answers 502; a connect or response-head timeout
answers 504; a stalled or invalid request body answers 408 or 400. These
local answers carry a short text body. A failure after the response has
started abandons it: HTTP/1.1 closes the connection, and HTTP/2 and HTTP/3
reset the stream. WebSocket and other upgrades are not forwarded. Writes to
a slow client are not timed, as for files.

## Responses

Static servers answer every request themselves: `GET /healthz` returns
`ok`, `GET` and `HEAD` serve files, `OPTIONS` answers 204 with `Allow: GET,
HEAD, OPTIONS`, and `POST`, `PUT`, `DELETE`, `PATCH`, and `TRACE` answer 405. With
`http.mode = "redirect"` the plain listener answers every request with 308
to `https://HOST[:tls.port]` plus the request path and query. HOST is the
request host, lowercase and without its port, when it matches a
`server_names` entry of the servers sharing the listener (exact or
wildcard), and `redirect_host` otherwise, so an unknown host never chooses
the redirect target.

Files keep eventloop's static-file rules: weak ETags from size, nanosecond
mtime/ctime, and file identity; `If-None-Match` before `If-Modified-Since`
before a single `Range`; 304, 206, and 416 responses; directory redirects to
a trailing slash; `index.html` preference; and listings of at most 4096
entries and 1 MiB of HTML (500 `directory listing too large` beyond). Every
path component is opened without following symbolic links, `..` segments
are rejected, and a FIFO or device answers 404 without blocking. Bodies of
16 KiB or less are read and sent with their header; larger ones go out as
file sends.

**Compression.** With `precompressed`, a compressible file (text, JSON, XML,
JavaScript, SVG, WebAssembly) is served from `FILE.br`, else `FILE.gz`, when
that regular file exists beside it and `Accept-Encoding` accepts the coding
(`q=0` refuses it). The variant keeps the original's `Content-Type`, has its
own validators, and supports ranges. With `gzip`, a compressible file of
`gzip_min_size` to `gzip_max_size` bytes without a precompressed variant is
compressed while sending, 16 KiB at a time: its ETag gains a `-gzip` suffix,
it has no `Content-Length` (HTTP/1.1 uses chunked coding), and `Range` is
ignored. Compressible responses carry `Vary: accept-encoding` whenever either
option is on.

**Policies.** `headers` adds each field to every Stonegate response,
including errors and redirects. Names are lowercase and cannot be fields
Stonegate manages (`cache-control`, `content-*`, `etag`, `last-modified`,
`vary`, `allow`, `alt-svc`, `location`, `date`, `accept-ranges`, or
connection-specific fields); values are visible ASCII, at most 1024 bytes.
`cache_control` sets `Cache-Control` on file responses (200, 206, 304, 416):
the longest matching `"/prefix"` of the decoded path wins, else the longest
`"*.ext"` suffix of the served file's name (so `/` matches `*.html` through
`index.html`). `error_pages` serves a regular file of at most 1 MiB from the
server's root as the body of that error status, with its own content type;
a missing page falls back to an empty body.

Errors produced inside eventloop before a request reaches Stonegate (bad
syntax, oversized heads or bodies, timeouts) keep eventloop's empty
responses and are not logged.

## Access logs

Each line follows the Combined Log Format, then the request host in quotes
and the seconds taken:

```text
203.0.113.7 - - [18/Oct/2026:13:05:01 +0000] "GET /a.css HTTP/2" 200 512 "https://site/" "curl/8" "site" 0.001
```

eventloop does not expose the peer address, so the client field is `-`
unless `real_ip_header` names a field set by a trusted proxy; its first
comma-separated entry is logged. Times are UTC. Quotes, backslashes, and
non-printing bytes are written as `\xHH`. The byte count is the body sent
(0 for HEAD and 304), or `-` when sending failed. Servers may share a log
file. Workers append lines to memory, and one thread writes every log at
least every 200 ms; while 4 MiB is waiting for a log, further lines are
dropped and the count is printed to standard error, so a slow disk never
blocks requests.

## Signals and lifecycle

`stonegate --config FILE --check` validates the merged configuration, looks
up the account, and loads TLS credentials, document roots, and access logs
(creating missing log files) without opening listening sockets or starting
an event loop. It does not predict port availability or validate
certificate trust.

**SIGHUP** reopens every access log by path (for log rotation) and reloads
every certificate and key. Reloading is all or nothing: if any file fails
to load, the error is printed and every listener keeps its certificate.
Otherwise each worker opens a new TLS and HTTP/3 listener beside each old
one (both use `SO_REUSEPORT`) and then closes the old listener. Open TCP
connections continue on the certificate they negotiated; HTTP/3 connections
close with their listener and clients reconnect. A TCP connection queued
in the old listener's backlog at that moment may be reset. Configuration
files are not reread; restart for other changes.

**SIGINT or SIGTERM** closes every TCP listener, then waits up to
`shutdown_seconds` for requests already being handled to finish, while
idle keep-alive connections are left alone; a second signal ends the wait.
Then HTTP/3 listeners close and the event loops shut down at once,
cancelling whatever remains. `shutdown_seconds = 0` skips the wait.

**`user` and `group`.** Once every listener is open, Stonegate drops root:
it sets supplementary groups from the user, then the group (by default the
user's primary group), then the user, and fails if root can be regained.
Configuration, roots, logs, and credentials are opened before the switch;
reloads read certificates as the new user, so they must stay readable to
it. On Linux each worker keeps `CAP_NET_BIND_SERVICE` through the switch,
so reloads can reopen ports below 1024; macOS lets any user bind them. A
process not started as root accepts only its own account.

## Bounds and threads

Limits: 16 servers, 32 files including the main file, include depth 8 (main
file is depth 1), 64 KiB per file, 1 MiB combined input, 2048 TOML nodes and
64 KiB decoded strings per file. Repeated/cyclic includes are rejected using
canonical paths. Capacity failures produce explicit errors. Includes use
ordinary filesystem access; only load trusted configuration files.

Stonegate runs on Linux, macOS, and other POSIX systems. With `workers`
above 1, each worker thread runs its own loop; routers, roots, logs, and TLS
contexts are shared, and HTTP/3 capacities and coroutine pools apply per
worker. `worker_mode` picks how connections reach workers; `auto` is
`reuse_port` on Linux and `handoff` elsewhere.

- `reuse_port`: every worker opens every listener with SO_REUSEPORT, and the
  kernel spreads TCP connections and UDP datagrams across workers. HTTP/3
  connection IDs carry the worker index, and each HTTP/3 server's endpoints
  form a worker group that forwards packets to the worker owning the
  connection, so a client whose address changes keeps its connection (see
  eventloop's [QUIC port sharing](https://github.com/ArdaKemal/eventloop/blob/main/docs/quic.md#port-sharing)).
  A reload gives the new listeners a new worker group. It needs a kernel that
  balances shared ports, so it is rejected outside Linux.
- `handoff`: worker 0 opens the only listeners and hands accepted TCP
  connections to every worker in turn (eventloop's `serving_loops`). HTTP/3
  runs on worker 0 alone. Accepting is slower than `reuse_port` but works on
  every platform.

The first startup error stops every worker.
