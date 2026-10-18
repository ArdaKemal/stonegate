#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace stonegate::toml_lexer {

enum class token_kind {
    atom, basic_string, literal_string, multiline_basic_string,
    multiline_literal_string, equals, comma, left_bracket, right_bracket,
    left_brace, right_brace, newline, end, invalid
};

struct token {
    token_kind kind;
    std::string_view raw;
    std::size_t offset;
};

// Tokens borrow the input; neither scanning nor validation allocates.
class lexer {
public:
    explicit lexer(std::string_view input) : input_(input)
    {
        invalid_utf8_ = find_invalid_utf8(input);
    }

    auto next() -> token
    {
        if (invalid_utf8_ != input_.size()) {
            const auto offset = invalid_utf8_;
            invalid_utf8_ = input_.size();
            position_ = input_.size();
            return {token_kind::invalid, input_.substr(offset, 1), offset};
        }
        while (position_ < input_.size()) {
            const auto c = input_[position_];
            if (c == ' ' || c == '\t') {
                ++position_;
                continue;
            }
            if (c != '#') break;
            ++position_;
            while (position_ < input_.size() && input_[position_] != '\n'
                   && input_[position_] != '\r') {
                if (forbidden_control(input_[position_])) return invalid(position_);
                ++position_;
            }
        }
        const auto start = position_;
        if (start == input_.size()) return {token_kind::end, {}, start};
        const auto c = input_[position_++];
        switch (c) {
        case '=': return make(token_kind::equals, start);
        case ',': return make(token_kind::comma, start);
        case '[': return make(token_kind::left_bracket, start);
        case ']': return make(token_kind::right_bracket, start);
        case '{': return make(token_kind::left_brace, start);
        case '}': return make(token_kind::right_brace, start);
        case '\n': return make(token_kind::newline, start);
        case '\r':
            if (position_ == input_.size() || input_[position_] != '\n')
                return invalid(start);
            ++position_;
            return make(token_kind::newline, start);
        case '\"': case '\'': return quoted(start, c);
        default: break;
        }
        if (forbidden_control(c)) return invalid(start);
        while (position_ < input_.size()) {
            const auto current = input_[position_];
            // RFC 3339 permits exactly one space between a date and time.
            if (current == ' ' && position_ - start == 10
                && date_prefix(start) && time_prefix(position_ + 1)) {
                ++position_;
                continue;
            }
            if (current == ' ' || current == '\t' || current == '\n'
                || current == '\r' || current == '#' || current == '='
                || current == ',' || current == '[' || current == ']'
                || current == '{' || current == '}' || current == '\"'
                || current == '\'') break;
            if (forbidden_control(current)) return invalid(position_);
            ++position_;
        }
        return make(token_kind::atom, start);
    }

private:
    std::string_view input_;
    std::size_t position_ = 0;
    std::size_t invalid_utf8_;

    static auto forbidden_control(char c) -> bool
    {
        const auto byte = static_cast<unsigned char>(c);
        return (byte < 0x20 && byte != 0x09) || byte == 0x7f;
    }

    static auto digit(char c) -> bool { return c >= '0' && c <= '9'; }

    auto date_prefix(std::size_t start) const -> bool
    {
        for (std::size_t i = 0; i < 10; ++i) {
            if (i == 4 || i == 7) {
                if (input_[start + i] != '-') return false;
            } else if (!digit(input_[start + i])) return false;
        }
        return true;
    }

    auto time_prefix(std::size_t start) const -> bool
    {
        return input_.size() - start >= 5 && digit(input_[start])
            && digit(input_[start + 1]) && input_[start + 2] == ':'
            && digit(input_[start + 3]) && digit(input_[start + 4]);
    }

    auto make(token_kind kind, std::size_t start) const -> token
    {
        return {kind, input_.substr(start, position_ - start), start};
    }

    auto invalid(std::size_t offset) -> token
    {
        position_ = input_.size();
        return {token_kind::invalid, input_.substr(offset, 1), offset};
    }

    static auto hex(char c) -> int
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    auto quoted(std::size_t start, char quote) -> token
    {
        const bool basic = quote == '\"';
        const bool multiline = input_.size() - position_ >= 2
            && input_[position_] == quote && input_[position_ + 1] == quote;
        if (multiline) position_ += 2;
        const auto kind = basic
            ? (multiline ? token_kind::multiline_basic_string : token_kind::basic_string)
            : (multiline ? token_kind::multiline_literal_string : token_kind::literal_string);
        while (position_ < input_.size()) {
            const auto offset = position_;
            const auto c = input_[position_++];
            if (c == quote) {
                if (!multiline) return make(kind, start);
                std::size_t count = 1;
                while (position_ < input_.size() && input_[position_] == quote && count < 5) {
                    ++position_;
                    ++count;
                }
                // Up to two quotes can immediately precede a closing delimiter.
                if (count >= 3) return make(kind, start);
                continue;
            }
            if (c == '\n' || c == '\r') {
                if (!multiline) return invalid(offset);
                if (c == '\r') {
                    if (position_ == input_.size() || input_[position_] != '\n')
                        return invalid(offset);
                    ++position_;
                }
                continue;
            }
            if (forbidden_control(c)) return invalid(offset);
            if (!basic || c != '\\') continue;
            if (position_ == input_.size()) return invalid(offset);
            const auto escaped = input_[position_++];
            if (multiline && (escaped == ' ' || escaped == '\t'
                              || escaped == '\n' || escaped == '\r')) {
                // A continuation requires a newline before any non-whitespace.
                auto cursor = position_ - 1;
                while (cursor < input_.size() && (input_[cursor] == ' ' || input_[cursor] == '\t'))
                    ++cursor;
                if (cursor == input_.size()) return invalid(offset);
                if (input_[cursor] == '\r') {
                    if (cursor + 1 == input_.size() || input_[cursor + 1] != '\n')
                        return invalid(cursor);
                    ++cursor;
                } else if (input_[cursor] != '\n') return invalid(offset);
                position_ = cursor + 1;
                continue;
            }
            if (escaped == 'b' || escaped == 't' || escaped == 'n'
                || escaped == 'f' || escaped == 'r' || escaped == 'e'
                || escaped == '\"' || escaped == '\\') continue;
            const std::size_t width = escaped == 'x' ? 2 : escaped == 'u' ? 4 : escaped == 'U' ? 8 : 0;
            if (width == 0 || input_.size() - position_ < width) return invalid(offset);
            std::uint32_t scalar = 0;
            for (std::size_t i = 0; i < width; ++i) {
                const auto value = hex(input_[position_++]);
                if (value < 0) return invalid(position_ - 1);
                scalar = scalar * 16 + static_cast<std::uint32_t>(value);
            }
            if (scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff))
                return invalid(offset);
        }
        return invalid(start);
    }

    static auto find_invalid_utf8(std::string_view text) -> std::size_t
    {
        for (std::size_t i = 0; i < text.size();) {
            const auto start = i;
            const auto first = static_cast<unsigned char>(text[i++]);
            if (first < 0x80) continue;
            unsigned remaining;
            std::uint32_t scalar;
            std::uint32_t minimum;
            if (first >= 0xc2 && first <= 0xdf) { remaining = 1; scalar = first & 0x1f; minimum = 0x80; }
            else if (first >= 0xe0 && first <= 0xef) { remaining = 2; scalar = first & 0x0f; minimum = 0x800; }
            else if (first >= 0xf0 && first <= 0xf4) { remaining = 3; scalar = first & 0x07; minimum = 0x10000; }
            else return start;
            if (text.size() - i < remaining) return start;
            while (remaining-- > 0) {
                const auto continuation = static_cast<unsigned char>(text[i++]);
                if ((continuation & 0xc0) != 0x80) return start;
                scalar = (scalar << 6) | (continuation & 0x3f);
            }
            if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff))
                return start;
        }
        return text.size();
    }
};

} // namespace stonegate::toml_lexer
