#!/usr/bin/env bash
set -euo pipefail

server=${1:?usage: smoke.sh /path/to/stonegate}
work=$(mktemp -d)
server_pid=
cleanup() {
    local status=$?
    trap - EXIT
    set +e
    if [[ -n "$server_pid" ]]; then
        kill -INT "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if (( status != 0 )); then
        for log in "$work"/server.log "$work"/server2.log "$work"/server3.log; do
            if [[ -f "$log" ]]; then
                echo "Stonegate log: $log" >&2
                cat "$log" >&2
            fi
        done
    fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT

mkdir "$work/root"
printf 'stonegate-ok\n' > "$work/root/index.html"
mkdir "$work/root/files"
printf 'listed\n' > "$work/root/files/asset.txt"
: > "$work/root/files/empty.bin"
awk 'BEGIN { for (i = 0; i < 20000; ++i) printf "%c", 65 + i % 26 }' \
    > "$work/root/files/large.txt"
printf 'outside\n' > "$work/outside.txt"
ln -s "$work/outside.txt" "$work/root/leak.txt"
mkdir "$work/root/listing" "$work/root/withindex" "$work/root/huge"
printf 'b\n' > "$work/root/listing/b.txt"
printf 'a\n' > "$work/root/listing/a&b.txt"
printf 'h\n' > "$work/root/listing/.hidden"
mkdir "$work/root/listing/sub"
ln -s "$work/outside.txt" "$work/root/listing/leak"
printf 'index body\n' > "$work/root/withindex/index.html"
for index in $(seq -w 1 4097); do : > "$work/root/huge/f$index"; done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1

mkdir "$work/config"
expect_config_error() {
    local expected=$1 contents=$2
    printf '%s\n' "$contents" > "$work/config/invalid.toml"
    if "$server" --config "$work/config/invalid.toml" >"$work/config-error.log" 2>&1; then
        echo "config unexpectedly accepted: $expected" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected" "$work/config-error.log"; then
        echo "config error missing: $expected" >&2
        cat "$work/config-error.log" >&2
        exit 1
    fi
    if grep -Fq 'PRIVATE_SENTINEL_739' "$work/config-error.log"; then
        echo 'config error exposed a private value' >&2
        exit 1
    fi
}
expect_config_error 'duplicate key' $'[defaults]\nroot="../root"\nroot="../root"'
expect_config_error 'unknown setting' $'[defaults]\nroot="../root"\nunknown=true'
expect_config_error 'invalid syntax' $'[defaults]\nroot="../root"\nhttp-port'
expect_config_error 'wrong TOML type' $'[defaults]\nroot="../root"\nhttp.port="abc"'
expect_config_error 'wrong TOML type' $'[defaults]\nroot="../root"\ntls.http2="yes"'
expect_config_error 'key-password requires TLS credentials' $'[defaults]\nroot="../root"\ntls.key_password="PRIVATE_SENTINEL_739"'
expect_config_error 'must be supplied together' $'[defaults]\nroot="../root"\ntls.certificate="../cert.pem"'
expect_config_error 'requires certificate and private-key' $'[defaults]\nroot="../root"\nhttp3.port=8444'
expect_config_error 'http3-connections has an invalid value' $'[defaults]\nroot="../root"\nhttp3.connections=257'
expect_config_error 'http3-requests has an invalid value' $'[defaults]\nroot="../root"\nhttp3.requests=8193'
expect_config_error 'TLS credentials and a TLS port are required' $'[defaults]\nroot="../root"\nhttp.mode="redirect"'
expect_config_error 'overlapping listening endpoints' $'[defaults]\nroot="../root"\ntls.certificate="../cert.pem"\ntls.private_key="../key.pem"\nhttp.port=8443'
if "$server" --config "$work/config/invalid.toml" --config "$work/config/invalid.toml" \
    >"$work/config-error.log" 2>&1; then
    echo 'duplicate --config unexpectedly accepted' >&2; exit 1
fi
grep -Fq 'duplicate --config' "$work/config-error.log" || {
    cat "$work/config-error.log" >&2; exit 1;
}
echo 'Config validation and secret redaction: PASS'

http_port=$((20000 + RANDOM % 20000))
https_port=$((40000 + RANDOM % 20000))
http3_port=$https_port
"$server" --root "$work/root" --bind 127.0.0.1 \
    --http-mode redirect --redirect-host localhost \
    --http-port "$http_port" --https-port "$https_port" --http3-port "$http3_port" \
    --http3-connections 16 --http3-requests 64 \
    --directory-listing \
    --certificate "$work/cert.pem" --private-key "$work/key.pem" \
    >"$work/server.log" 2>&1 &
server_pid=$!

ready=0
for _ in {1..100}; do
    if curl --silent --max-time 1 "http://127.0.0.1:$http_port/" >/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$work/server.log" >&2
        exit 1
    fi
    sleep 0.1
done
if (( !ready )); then
    cat "$work/server.log" >&2
    exit 1
fi

redirect=$(curl --silent --http1.1 --output /dev/null --write-out '%{http_code} %{redirect_url}' \
    "http://127.0.0.1:$http_port/")
[[ "$redirect" == "308 https://localhost:$https_port/" ]] || {
    echo "unexpected redirect: $redirect" >&2
    exit 1
}

body=$(curl --silent --fail --http1.1 --cacert "$work/cert.pem" \
    --resolve "localhost:$https_port:127.0.0.1" "https://localhost:$https_port/")
[[ "$body" == stonegate-ok ]] || { echo 'HTTP/1.1 body mismatch' >&2; exit 1; }
echo 'HTTP/1.1 redirect and TLS response: PASS'

health=$(curl --silent --fail --http1.1 --cacert "$work/cert.pem" \
    --resolve "localhost:$https_port:127.0.0.1" "https://localhost:$https_port/healthz")
[[ "$health" == ok ]] || { echo "unexpected /healthz body: $health" >&2; exit 1; }
echo 'HTTP/1.1 /healthz route: PASS'

if curl --version | grep -q HTTP2; then
    health=$(curl --silent --fail --http2 --cacert "$work/cert.pem" \
        --resolve "localhost:$https_port:127.0.0.1" "https://localhost:$https_port/healthz")
    [[ "$health" == ok ]] || { echo "unexpected HTTP/2 /healthz body: $health" >&2; exit 1; }
    echo 'HTTP/2 /healthz route: PASS'
    version=$(curl --silent --fail --http2 --cacert "$work/cert.pem" \
        --resolve "localhost:$https_port:127.0.0.1" \
        --output "$work/h2-body" --write-out '%{http_version}' \
        "https://localhost:$https_port/")
    [[ "$version" == 2 && $(cat "$work/h2-body") == stonegate-ok ]] || {
        echo "HTTP/2 expected, got version $version" >&2
        exit 1
    }
    echo 'TLS HTTP/2 response: PASS'
else
    echo 'TLS HTTP/2 response: SKIP (curl lacks HTTP2)'
fi

header_value() {
    awk -v wanted="$2" '
        { sub(/\r$/, ""); colon = index($0, ":")
          if (colon && tolower(substr($0, 1, colon - 1)) == wanted) {
              value = substr($0, colon + 1)
              sub(/^[ \t]*/, "", value)
              print value
              exit
          } }
    ' "$1"
}

check_static_file_headers() {
    local label=$1
    shift
    local url="https://localhost:$https_port/files/asset.txt"
    local -a transport=("$@")
    local common=(--silent --show-error --max-time 8 --cacert "$work/cert.pem"
        --resolve "localhost:$https_port:127.0.0.1")
    local status etag modified actual
    status=$(curl "${common[@]}" "${transport[@]}" --dump-header "$work/headers" \
        --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 200 && $(cat "$work/body") == listed ]] || {
        echo "$label baseline response failed: $status" >&2; exit 1;
    }
    etag=$(header_value "$work/headers" etag)
    modified=$(header_value "$work/headers" last-modified)
    [[ -n "$etag" && -n "$modified" ]] || {
        echo "$label validators missing" >&2; exit 1;
    }
    : > "$work/body"
    status=$(curl "${common[@]}" "${transport[@]}" -H "If-None-Match: $etag" \
        --dump-header "$work/headers" --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 304 && ! -s "$work/body" ]] || {
        echo "$label If-None-Match failed: $status" >&2; exit 1;
    }
    : > "$work/body"
    status=$(curl "${common[@]}" "${transport[@]}" -H "If-None-Match: ${etag#W/}" \
        -H 'Range: bytes=1-3' --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 304 && ! -s "$work/body" ]] || {
        echo "$label weak ETag comparison or conditional precedence failed: $status" >&2; exit 1;
    }
    : > "$work/body"
    status=$(curl "${common[@]}" "${transport[@]}" -H "If-Modified-Since: $modified" \
        --dump-header "$work/headers" --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 304 && ! -s "$work/body" ]] || {
        echo "$label If-Modified-Since failed: $status" >&2; exit 1;
    }
    status=$(curl "${common[@]}" "${transport[@]}" -H 'If-None-Match: "different"' \
        -H "If-Modified-Since: $modified" --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 200 ]] || { echo "$label validator precedence failed: $status" >&2; exit 1; }
    : > "$work/body"
    status=$(curl "${common[@]}" "${transport[@]}" -H 'If-None-Match: "nope"' \
        -H "If-None-Match: $etag" --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 304 && ! -s "$work/body" ]] || {
        echo "$label repeated If-None-Match fallback failed: $status" >&2; exit 1;
    }
    status=$(curl "${common[@]}" "${transport[@]}" -H 'Range: bytes=0-0' \
        -H 'Range: bytes=2-3' --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 200 && $(cat "$work/body") == listed ]] || {
        echo "$label repeated Range fallback failed: $status" >&2; exit 1;
    }
    for range in 'bytes=1-3' 'bytes=1-' 'bytes=-3'; do
        status=$(curl "${common[@]}" "${transport[@]}" -H "Range: $range" \
            --dump-header "$work/headers" --output "$work/body" --write-out '%{http_code}' "$url")
        case "$range" in
            'bytes=1-3') actual=ist;;
            'bytes=1-') actual=$'isted\n';;
            'bytes=-3') actual=$'ed\n';;
        esac
        [[ "$status" == 206 && $(cat "$work/body"; printf x) == "${actual}x" ]] || {
            echo "$label range $range failed: $status" >&2; exit 1;
        }
        [[ -n $(header_value "$work/headers" content-range) ]] || {
            echo "$label Content-Range missing" >&2; exit 1;
        }
    done
    : > "$work/body"
    status=$(curl "${common[@]}" "${transport[@]}" -H 'Range: bytes=99-' \
        --dump-header "$work/headers" --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 416 && ! -s "$work/body" &&
       $(header_value "$work/headers" content-range) == 'bytes */7' ]] || {
        echo "$label unsatisfiable range failed: $status" >&2; exit 1;
    }
    status=$(curl "${common[@]}" "${transport[@]}" -H 'Range: bytes=0-1,3-4' \
        --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 200 && $(cat "$work/body") == listed ]] || {
        echo "$label multiple range fallback failed: $status" >&2; exit 1;
    }
    status=$(curl "${common[@]}" "${transport[@]}" --head -H 'Range: bytes=1-3' \
        --dump-header "$work/headers" --output /dev/null --write-out '%{http_code} %{size_download}' "$url")
    [[ "$status" == '206 0' && $(header_value "$work/headers" content-length) == 3 ]] || {
        echo "$label HEAD range failed: $status" >&2; exit 1;
    }
    status=$(curl "${common[@]}" "${transport[@]}" -H 'Range: bytes=10000-12000' \
        --output "$work/body" --write-out '%{http_code}' \
        "https://localhost:$https_port/files/large.txt")
    dd if="$work/root/files/large.txt" of="$work/expected" bs=1 skip=10000 count=2001 \
        status=none
    [[ "$status" == 206 ]] && cmp -s "$work/expected" "$work/body" || {
        echo "$label streamed range failed: $status" >&2; exit 1;
    }
    touch -r "$work/root/files/asset.txt" "$work/mtime-reference"
    printf 'edited\n' > "$work/root/files/asset.txt"
    touch -r "$work/mtime-reference" "$work/root/files/asset.txt"
    status=$(curl "${common[@]}" "${transport[@]}" -H "If-None-Match: $etag" \
        --dump-header "$work/headers" --output "$work/body" --write-out '%{http_code}' "$url")
    [[ "$status" == 200 && $(cat "$work/body") == edited &&
       $(header_value "$work/headers" etag) != "$etag" ]] || {
        echo "$label stale ETag after same-size replacement and restored mtime" >&2; exit 1;
    }
    printf 'listed\n' > "$work/root/files/asset.txt"
    touch -r "$work/mtime-reference" "$work/root/files/asset.txt"
    local empty_url="https://localhost:$https_port/files/empty.bin"
    status=$(curl "${common[@]}" "${transport[@]}" --dump-header "$work/headers" \
        --output "$work/body" --write-out '%{http_code}' "$empty_url")
    [[ "$status" == 200 && ! -s "$work/body" &&
       $(header_value "$work/headers" content-length) == 0 ]] || {
        echo "$label empty file baseline failed: $status" >&2; exit 1;
    }
    status=$(curl "${common[@]}" "${transport[@]}" -H 'Range: bytes=0-' \
        --dump-header "$work/headers" --output "$work/body" --write-out '%{http_code}' "$empty_url")
    [[ "$status" == 416 && ! -s "$work/body" &&
       $(header_value "$work/headers" content-range) == 'bytes */0' ]] || {
        echo "$label empty file range failed: $status" >&2; exit 1;
    }
    echo "$label conditional and range responses: PASS"
}

check_directory_listing() {
    local label=$1
    shift
    local common=(--silent --show-error --max-time 8 --cacert "$work/cert.pem"
        --resolve "localhost:$https_port:127.0.0.1")
    curl "${common[@]}" "$@" --output "$work/listing-$label.body" \
        "https://localhost:$https_port/listing/"
    local body; body=$(<"$work/listing-$label.body")
    [[ "$body" == *'href="a%26b.txt"'* && "$body" == *'a&amp;b.txt'* &&
       "$body" == *'.hidden'* && "$body" == *'href="sub/"'* &&
       "$body" == *'leak'* ]] || {
        echo "$label listing entry or escaping failed" >&2; exit 1;
    }
    local ordered
    ordered=$(grep -o '[^<>]*</a>' "$work/listing-$label.body" | sed 's#</a>$##' | paste -sd, -)
    [[ "$ordered" == '.hidden,a&amp;b.txt,b.txt,leak,sub/' ]] || {
        echo "$label listing order failed: $ordered" >&2; exit 1;
    }
    if [[ -f "$work/listing-reference.body" ]]; then
        cmp "$work/listing-reference.body" "$work/listing-$label.body" || {
            echo "$label listing differs from the first protocol" >&2; exit 1;
        }
    else
        cp "$work/listing-$label.body" "$work/listing-reference.body"
    fi
    local index
    index=$(curl "${common[@]}" "$@" "https://localhost:$https_port/withindex/")
    [[ "$index" == 'index body' ]] || { echo "$label index preference failed" >&2; exit 1; }
    local code
    code=$(curl "${common[@]}" "$@" --output "$work/link.body" --write-out '%{http_code}' \
        "https://localhost:$https_port/listing/leak")
    [[ "$code" == 404 ]] && ! grep -q outside "$work/link.body" || {
        echo "$label symlink entry exposed content" >&2; exit 1;
    }
    code=$(curl "${common[@]}" "$@" --output "$work/huge.body" --write-out '%{http_code}' \
        "https://localhost:$https_port/huge/")
    [[ "$code" == 500 ]] && grep -q 'directory listing too large' "$work/huge.body" || {
        echo "$label listing limit failed: $code" >&2; exit 1;
    }
    echo "$label directory listing: PASS"
}

check_static_file_headers 'HTTP/1.1' --http1.1
check_directory_listing http1 --http1.1
if curl --version | grep -q HTTP2; then
    check_static_file_headers 'HTTP/2' --http2
    check_directory_listing http2 --http2
fi

if curl --version | grep -Eq '(^|[[:space:]])HTTP3([[:space:]]|$)'; then
    check_static_file_headers 'HTTP/3' --http3-only
    check_directory_listing http3 --http3-only
    h3_url="https://localhost:$http3_port/"
    h3_resolve="localhost:$http3_port:127.0.0.1"
    health=$(curl --silent --show-error --fail --http3-only --max-time 8 \
        --cacert "$work/cert.pem" --resolve "$h3_resolve" "${h3_url}healthz")
    [[ "$health" == ok ]] || { echo "unexpected HTTP/3 /healthz body: $health" >&2; exit 1; }
    echo 'HTTP/3 /healthz route: PASS'
    for round in 1 2 3; do
        get_result=$(curl --silent --show-error --fail --http3-only --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --dump-header "$work/h3-get-$round.headers" \
            --output "$work/h3-get-$round.body" \
            --write-out '%{http_code} %{http_version}' "$h3_url")
        [[ "$get_result" == '200 3' ]] || {
            echo "HTTP/3 GET expected 200 and version 3, got $get_result" >&2; exit 1;
        }
        cmp -s "$work/root/index.html" "$work/h3-get-$round.body" || {
            echo "HTTP/3 GET body mismatch in round $round" >&2; exit 1;
        }

        head_result=$(curl --silent --show-error --fail --http3-only --head --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --dump-header "$work/h3-head-$round.headers" --output /dev/null \
            --write-out '%{http_code} %{http_version} %{size_download}' "$h3_url")
        [[ "$head_result" == '200 3 0' ]] || {
            echo "HTTP/3 HEAD expected 200, version 3, and no body; got $head_result" >&2; exit 1;
        }
        expected_length=$(wc -c < "$work/root/index.html" | tr -d '[:space:]')
        actual_length=$(header_value "$work/h3-head-$round.headers" content-length)
        [[ "$actual_length" == "$expected_length" ]] || {
            echo "HTTP/3 HEAD Content-Length mismatch in round $round: $actual_length" >&2; exit 1;
        }

        options_result=$(curl --silent --show-error --fail --http3-only -X OPTIONS --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --dump-header "$work/h3-options-$round.headers" \
            --output "$work/h3-options-$round.body" \
            --write-out '%{http_code} %{http_version}' "$h3_url")
        [[ "$options_result" == '204 3' && ! -s "$work/h3-options-$round.body" ]] || {
            echo "HTTP/3 OPTIONS expected 204, version 3, and no body; got $options_result" >&2; exit 1;
        }
        allow=$(header_value "$work/h3-options-$round.headers" allow)
        [[ "$allow" == 'GET, HEAD, OPTIONS' ]] || {
            echo "HTTP/3 OPTIONS Allow mismatch in round $round: $allow" >&2; exit 1;
        }
        if grep -Eiq '^content-length:' "$work/h3-options-$round.headers"; then
            echo "HTTP/3 OPTIONS unexpectedly sent Content-Length in round $round" >&2; exit 1;
        fi

        after_result=$(curl --silent --show-error --fail --http3-only --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --output "$work/h3-after-$round.body" \
            --write-out '%{http_code} %{http_version}' "$h3_url")
        [[ "$after_result" == '200 3' ]] &&
            cmp -s "$work/root/index.html" "$work/h3-after-$round.body" || {
            echo "HTTP/3 GET after OPTIONS failed in round $round: $after_result" >&2; exit 1;
        }
    done
    echo 'HTTP/3 repeated GET, HEAD, OPTIONS, GET on fresh connections: PASS'
else
    echo 'HTTP/3 repeated GET, HEAD, OPTIONS, GET: SKIP (curl lacks HTTP3)'
fi

if ! kill -INT "$server_pid"; then
    cat "$work/server.log" >&2
    echo 'first Stonegate process could not receive SIGINT' >&2
    exit 1
fi
if wait "$server_pid"; then
    :
else
    status=$?
    cat "$work/server.log" >&2
    echo "first Stonegate process exited after SIGINT with status $status" >&2
    exit 1
fi
server_pid=

cat > "$work/config/tls.toml" <<EOF
[defaults]
root = "../root"
bind = "127.0.0.1"
[defaults.http]
mode = "redirect"
port = $http_port
[defaults.tls]
port = $https_port
certificate = "../cert.pem"
private_key = "../key.pem"
http2 = true
EOF
"$server" --http2 off --config "$work/config/tls.toml" --http-mode off \
    >"$work/server2.log" 2>&1 &
server_pid=$!
ready=0
for _ in {1..100}; do
    if curl --silent --fail --http1.1 --cacert "$work/cert.pem" \
        --resolve "localhost:$https_port:127.0.0.1" \
        "https://localhost:$https_port/" >/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
(( ready )) || { cat "$work/server2.log" >&2; exit 1; }
echo 'TLS listener rebind after SIGINT: PASS'
version=$(curl --silent --fail --http1.1 --cacert "$work/cert.pem" \
    --resolve "localhost:$https_port:127.0.0.1" \
    --output /dev/null --write-out '%{http_version}' \
    "https://localhost:$https_port/")
[[ "$version" == 1.1 ]] || { echo "HTTP/1.1 expected, got $version" >&2; exit 1; }
echo 'TLS HTTP/1.1 only: PASS'
echo 'Config-relative root and TLS paths with CLI overrides: PASS'

if ! kill -INT "$server_pid"; then
    cat "$work/server2.log" >&2
    echo 'second Stonegate process could not receive SIGINT' >&2
    exit 1
fi
if wait "$server_pid"; then
    :
else
    status=$?
    cat "$work/server2.log" >&2
    echo "second Stonegate process exited after SIGINT with status $status" >&2
    exit 1
fi
server_pid=

"$server" --root "$work/root" --bind 127.0.0.1 \
    --directory-listing --reuse-port \
    --http-port "$http_port" >"$work/server3.log" 2>&1 &
server_pid=$!
ready=0
for _ in {1..100}; do
    if curl --silent --fail --http1.1 "http://127.0.0.1:$http_port/" >/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
(( ready )) || { cat "$work/server3.log" >&2; exit 1; }
body=$(curl --silent --fail --http1.1 "http://127.0.0.1:$http_port/")
[[ "$body" == stonegate-ok ]] || { echo 'plain HTTP/1.1 body mismatch' >&2; exit 1; }
head_code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --head "http://127.0.0.1:$http_port/")
[[ "$head_code" == 200 ]] || { echo "HEAD returned $head_code" >&2; exit 1; }
listing=$(curl --silent --fail "http://127.0.0.1:$http_port/files/")
[[ "$listing" == *asset.txt* ]] || { echo 'directory listing missing asset' >&2; exit 1; }
for target in '/..%2foutside.txt' '/%2e%2e/outside.txt'; do
    code=$(curl --silent --path-as-is --output "$work/traversal.body" \
        --write-out '%{http_code}' "http://127.0.0.1:$http_port$target")
    [[ "$code" == 400 ]] && ! grep -q outside "$work/traversal.body" || {
        echo "path traversal unexpectedly served $target (status $code)" >&2; exit 1;
    }
done
code=$(curl --silent --output "$work/symlink.body" --write-out '%{http_code}' \
    "http://127.0.0.1:$http_port/leak.txt")
[[ "$code" == 404 ]] && ! grep -q outside "$work/symlink.body" || {
    echo "symlink outside document root unexpectedly served (status $code)" >&2; exit 1;
}
plain_url="http://127.0.0.1:$http_port/files/asset.txt"
plain_code=$(curl --silent --output "$work/plain-full.body" --write-out '%{http_code}' \
    -H 'Range: bytes=0-' "$plain_url")
[[ "$plain_code" == 206 && $(cat "$work/plain-full.body") == listed ]] || {
    echo "plain HTTP/1.1 open range failed: $plain_code" >&2; exit 1;
}
plain_code=$(curl --silent --output "$work/plain-range.body" --write-out '%{http_code}' \
    -H 'Range: bytes=1-3' "$plain_url")
[[ "$plain_code" == 206 && $(cat "$work/plain-range.body") == ist ]] || {
    echo "plain HTTP/1.1 suffix range failed: $plain_code" >&2; exit 1;
}
curl --silent --dump-header "$work/plain-headers" --output /dev/null "$plain_url"
plain_etag=$(header_value "$work/plain-headers" etag)
plain_code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    -H "If-None-Match: $plain_etag" "$plain_url")
[[ -n "$plain_etag" && "$plain_code" == 304 ]] || {
    echo "plain HTTP/1.1 If-None-Match failed: $plain_code" >&2; exit 1;
}
echo 'Plain HTTP/1.1 response: PASS'
echo 'HEAD and directory listing: PASS'
echo 'Path traversal and outside-root symlink rejection: PASS'

if ! kill -INT "$server_pid" || ! wait "$server_pid"; then
    cat "$work/server3.log" >&2; exit 1
fi
server_pid=
cat > "$work/config/plain.toml" <<EOF
# Plain server equivalent to the preceding CLI run.
[defaults]
root = "../root"
bind = "127.0.0.1"
directory_listing = true
reuse_port = true
[defaults.http]
port = $http_port
EOF
"$server" --config "$work/config/plain.toml" >"$work/server4.log" 2>&1 &
server_pid=$!
ready=0
for _ in {1..100}; do
    if curl --silent --fail "http://127.0.0.1:$http_port/" >"$work/config-body"; then
        ready=1; break
    fi
    sleep 0.1
done
(( ready )) || { cat "$work/server4.log" >&2; exit 1; }
cmp -s "$work/root/index.html" "$work/config-body" || {
    echo 'config response differs from CLI response' >&2; exit 1;
}
listing=$(curl --silent --fail "http://127.0.0.1:$http_port/files/")
[[ "$listing" == *asset.txt* ]] || { echo 'config directory listing missing asset' >&2; exit 1; }
echo 'Config and CLI plain HTTP equivalence: PASS'

if ! kill -INT "$server_pid" || ! wait "$server_pid"; then
    cat "$work/server4.log" >&2; exit 1
fi
server_pid=
mkdir "$work/other-root"
printf 'override-ok\n' > "$work/other-root/index.html"
"$server" --config "$work/config/plain.toml" --root "$work/other-root" \
    --no-directory-listing --no-reuse-port >"$work/server5.log" 2>&1 &
server_pid=$!
ready=0
for _ in {1..100}; do
    if [[ $(curl --silent --max-time 1 "http://127.0.0.1:$http_port/" || true) == override-ok ]]; then
        ready=1; break
    fi
    sleep 0.1
done
(( ready )) || { cat "$work/server5.log" >&2; exit 1; }
code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "http://127.0.0.1:$http_port/files/")
[[ "$code" != 200 ]] || { echo 'CLI directory-listing override failed' >&2; exit 1; }
echo 'CLI root and boolean overrides: PASS'
