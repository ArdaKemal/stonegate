# TOML parser

Stonegate reads its configuration with `src/toml.h`. `stonegate::parse_toml(input,
nodes, decoded_strings)` synchronously parses [TOML 1.1.0](https://toml.io/en/v1.1.0)
and returns `std::expected<toml_document, toml_error>`. Callers read files
separately.

- Input `string_view`, mutable `span<toml_value>`, and mutable `span<char>`
  are borrowed. Keep all backing buffers alive and unchanged while using any
  document/node/key/string view. Document copies share storage; reparsing
  invalidates previous views.
- Span sizes bound capacity. The root and each value/implicit table consume
  one node. Keys/plain strings may borrow input; escapes and newline
  normalization consume decoded storage. Exhaustion reports `node_capacity`
  or `string_capacity`; nesting/dotted paths beyond depth 64 report
  `nesting_limit`. Inspect `nodes_used()`/`strings_used()`.
- Errors carry `toml_error_code` and input byte offset: invalid UTF-8, duplicate
  keys, conflicting tables, invalid values, or limits. Failure may overwrite
  storage partially and returns no document; check success before access.
- `root()` is the unnamed table. `find(name)` matches one decoded key component;
  `find("a.b")` is one key, while `find("a")` then `find("b")` traverses.
  `at(index)` selects an array element; iteration visits children in source
  order. Lookup/indexing scan siblings. Check `type` before reading its value;
  applications validate schemas/ranges.
- Integers are signed 64-bit, floats `double`. Date/time retains kind and local
  fields; fractional seconds truncate to nanoseconds, omitted seconds are zero,
  and offsets remain minutes without UTC conversion.

Parsing uses caller storage and bounded local state and does not allocate.
