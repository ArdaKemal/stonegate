#pragma once

#include <algorithm>
#include <string_view>

namespace stonegate {

[[nodiscard]] constexpr auto lower(char value) noexcept -> char
{
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
}

// Compares text without case against an already lowercase string.
[[nodiscard]] inline auto equal_lowercase(std::string_view text, std::string_view lowercase) noexcept
    -> bool
{
    return text.size() == lowercase.size() &&
        std::ranges::equal(text, lowercase, [](char left, char right) { return lower(left) == right; });
}

[[nodiscard]] inline auto trim(std::string_view text) noexcept -> std::string_view
{
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

} // namespace stonegate
