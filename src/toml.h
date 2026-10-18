#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace stonegate {

enum class toml_type { table, array, string, integer, floating, boolean,
                       offset_datetime, local_datetime, local_date, local_time };
enum class toml_error_code { invalid_syntax, invalid_utf8, invalid_string,
    invalid_number, invalid_datetime, duplicate_key, conflicting_table,
    node_capacity, string_capacity, nesting_limit };
struct toml_error { toml_error_code code; std::size_t offset; };
struct toml_datetime {
    int year{}, month{}, day{}, hour{}, minute{}, second{};
    std::uint32_t nanosecond{}; // Additional fractional digits are truncated.
    int offset_minutes{};
};

// Nodes and decoded strings live in caller storage. Keys and plain strings may
// also borrow input; input and both storage spans must outlive the document.
// Child order follows source order. Table lookup is linear in its child count.
struct toml_value {
    toml_type type{toml_type::table};
    std::string_view key{}, string{};
    std::int64_t integer{};
    double floating{};
    bool boolean{};
    toml_datetime datetime{};
    toml_value* first_child{};
    toml_value* next_sibling{};
    // Reserved parser bookkeeping; callers must not modify nodes during use.
    toml_value* last_child{};
    unsigned parser_flags{};
    [[nodiscard]] auto find(std::string_view name) const noexcept -> const toml_value*;
    [[nodiscard]] auto at(std::size_t index) const noexcept -> const toml_value*;
    struct iterator {
        const toml_value* value{};
        auto operator*() const noexcept -> const toml_value& { return *value; }
        auto operator->() const noexcept -> const toml_value* { return value; }
        auto operator++() noexcept -> iterator& { value = value->next_sibling; return *this; }
        auto operator==(const iterator&) const noexcept -> bool = default;
    };
    auto begin() const noexcept -> iterator { return {first_child}; }
    auto end() const noexcept -> iterator { return {}; }
};
class toml_document {
public:
    toml_document(toml_value* root, std::size_t nodes, std::size_t strings) noexcept
        : root_(root), nodes_(nodes), strings_(strings) {}
    auto root() const noexcept -> const toml_value& { return *root_; }
    auto nodes_used() const noexcept -> std::size_t { return nodes_; }
    auto strings_used() const noexcept -> std::size_t { return strings_; }
private:
    toml_value* root_;
    std::size_t nodes_, strings_;
};

// Synchronous, portable TOML 1.1 parsing with no heap allocation. One node is
// consumed by the root and each value/implicit table. Escaped or normalized
// strings consume decoded storage. Depth (including dotted paths) is capped at
// 64. On error storage may be partially written; no document is returned.
[[nodiscard]] auto parse_toml(std::string_view input, std::span<toml_value> nodes,
    std::span<char> decoded_strings) noexcept -> std::expected<toml_document, toml_error>;

} // namespace stonegate
