# Fuzzing

libFuzzer harnesses with AddressSanitizer and UndefinedBehaviorSanitizer for
Stonegate's own parsing; eventloop's protocol parsers have their own in
eventloop's `fuzz/`. They need Clang 19 or newer and an eventloop source
checkout (`EVENTLOOP_SOURCE_DIR`), since two harnesses reach private
headers.

| Harness | Input and invariants |
| --- | --- |
| `fuzz_request_parsing` | Request paths, Host, Accept-Encoding, conditional and range fields, log and HTML text. Decoded paths have no `..` segment, opened files stay inside the document root, ranges stay inside the file, and `named_host` stays a plain host name |
| `fuzz_proxy_head` | Upstream response heads. Parsed fields are valid lowercase tokens with safe values, no connection-specific field survives, and site headers replace upstream ones |
| `fuzz_toml` | Configuration files |

```sh
CC=clang-20 CXX=clang++-20 cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF -DSTONEGATE_FUZZERS=ON -DEVENTLOOP_SOURCE_DIR=/path/to/eventloop
cmake --build build-fuzz -j --target fuzz_request_parsing
mkdir -p corpus/request_parsing
./build-fuzz/fuzz_request_parsing -max_total_time=600 corpus/request_parsing
```

A crash leaves `crash-<hash>` in the working directory; rerun the harness
with that file as its only argument to reproduce it.
