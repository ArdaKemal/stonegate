#include "toml.h"
#include "toml_lexer.h"

#include <array>
#include <charconv>
#include <cmath>
#include <limits>

namespace stonegate {
auto toml_value::find(std::string_view name) const noexcept -> const toml_value* {
    if (type != toml_type::table) return nullptr;
    for (auto* p = first_child; p; p = p->next_sibling) if (p->key == name) return p;
    return nullptr;
}
auto toml_value::at(std::size_t index) const noexcept -> const toml_value* {
    if (type != toml_type::array) return nullptr;
    auto* p = first_child;
    while (p && index--) p = p->next_sibling;
    return p;
}
namespace {
using toml_lexer::token_kind;
using toml_lexer::token;
constexpr unsigned defined = 1, dotted = 2, sealed = 4, array_tables = 8;
constexpr std::size_t max_depth = 64;
bool digit(char c) { return c >= '0' && c <= '9'; }
int hex(char c) {
    if (digit(c)) return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
bool bare(char c) { return digit(c) || (c >= 'a' && c <= 'z') ||
    (c >= 'A' && c <= 'Z') || c == '_' || c == '-'; }
class parser {
public:
    parser(std::string_view in, std::span<toml_value> ns, std::span<char> ss)
        : input(in), lex(in), nodes(ns), strings(ss) {}
    auto run() -> std::expected<toml_document, toml_error>;
private:
    std::string_view input;
    toml_lexer::lexer lex;
    token tok{};
    std::span<toml_value> nodes;
    std::span<char> strings;
    std::size_t used{}, chars{};
    toml_error error{toml_error_code::invalid_syntax, 0};
    bool failed{};
    void advance() { tok = lex.next(); if (tok.kind == token_kind::invalid) fail(toml_error_code::invalid_syntax); }
    bool fail(toml_error_code code, std::size_t offset = std::string_view::npos) {
        if (!failed) error = {code, offset == std::string_view::npos ? tok.offset : offset};
        failed = true; return false;
    }
    bool accept(token_kind k) { if (tok.kind != k) return false; advance(); return true; }
    bool expect(token_kind k) { return accept(k) || fail(toml_error_code::invalid_syntax); }
    void newlines() { while (!failed && tok.kind == token_kind::newline) advance(); }
    toml_value* node(toml_type t) {
        if (used == nodes.size()) { fail(toml_error_code::node_capacity); return nullptr; }
        auto* p = &nodes[used++]; *p = {}; p->type = t; return p;
    }
    void append(toml_value* parent, toml_value* p) {
        if (parent->last_child) parent->last_child->next_sibling = p;
        else parent->first_child = p;
        parent->last_child = p;
    }
    bool put(char c) { if (chars == strings.size()) return fail(toml_error_code::string_capacity);
        strings[chars++] = c; return true; }
    bool unicode(std::uint32_t cp) {
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return fail(toml_error_code::invalid_string);
        if (cp < 0x80) return put(static_cast<char>(cp));
        if (cp < 0x800) return put(static_cast<char>(0xc0 | (cp >> 6))) && put(static_cast<char>(0x80 | (cp & 63)));
        if (cp < 0x10000) return put(static_cast<char>(0xe0 | (cp >> 12))) && put(static_cast<char>(0x80 | ((cp >> 6) & 63))) && put(static_cast<char>(0x80 | (cp & 63)));
        return put(static_cast<char>(0xf0 | (cp >> 18))) && put(static_cast<char>(0x80 | ((cp >> 12) & 63))) && put(static_cast<char>(0x80 | ((cp >> 6) & 63))) && put(static_cast<char>(0x80 | (cp & 63)));
    }
    bool string_value(token t, std::string_view& out);
    bool keys(std::array<std::string_view, max_depth>& path, std::size_t& count);
    toml_value* descend(toml_value* p, std::string_view key, bool header);
    bool assignment(toml_value* table, std::size_t depth);
    bool value(toml_value* p, std::size_t depth);
    bool scalar(toml_value* p, std::string_view s);
    bool datetime(toml_value* p, std::string_view s);
    bool utf8();
};

bool parser::utf8() {
    for (std::size_t i = 0; i < input.size();) {
        auto c = static_cast<unsigned char>(input[i]);
        if (c < 128) { ++i; continue; }
        unsigned n; std::uint32_t cp;
        if (c >= 0xc2 && c <= 0xdf) { n = 2; cp = c & 31; }
        else if (c >= 0xe0 && c <= 0xef) { n = 3; cp = c & 15; }
        else if (c >= 0xf0 && c <= 0xf4) { n = 4; cp = c & 7; }
        else return fail(toml_error_code::invalid_utf8, i);
        if (input.size() - i < n) return fail(toml_error_code::invalid_utf8, i);
        for (unsigned j = 1; j < n; ++j) { auto b = static_cast<unsigned char>(input[i+j]);
            if ((b & 0xc0) != 0x80) return fail(toml_error_code::invalid_utf8, i+j);
            cp = (cp << 6) | (b & 63); }
        if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return fail(toml_error_code::invalid_utf8, i);
        i += n;
    }
    return true;
}
bool parser::string_value(token t, std::string_view& out) {
    bool multi = t.kind == token_kind::multiline_basic_string || t.kind == token_kind::multiline_literal_string;
    bool basic = t.kind == token_kind::basic_string || t.kind == token_kind::multiline_basic_string;
    std::size_t delim = multi ? 3 : 1;
    if (t.raw.size() < delim * 2) return fail(toml_error_code::invalid_string, t.offset);
    auto s = t.raw.substr(delim, t.raw.size() - delim * 2);
    if (multi && s.starts_with("\r\n")) s.remove_prefix(2);
    else if (multi && s.starts_with('\n')) s.remove_prefix(1);
    bool decode = s.find('\r') != s.npos || (basic && s.find('\\') != s.npos);
    std::size_t start = chars;
    for (std::size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '\r') {
            if (!multi || i + 1 == s.size() || s[i+1] != '\n') return fail(toml_error_code::invalid_string, t.offset + delim + i);
            ++i; if (decode && !put('\n')) return false; continue;
        }
        if ((c < 32 && c != '\t' && !(multi && c == '\n')) || c == 127) return fail(toml_error_code::invalid_string, t.offset + delim + i);
        if (basic && c == '\\') {
            if (++i == s.size()) return fail(toml_error_code::invalid_string, t.offset + delim + i);
            char e = s[i];
            if (multi && (e == ' ' || e == '\t' || e == '\n' || e == '\r')) {
                bool nl = false;
                while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) {
                    if (s[i] == '\n') nl = true;
                    if (s[i] == '\r' && (i + 1 == s.size() || s[i+1] != '\n')) return fail(toml_error_code::invalid_string);
                    ++i;
                }
                if (!nl) return fail(toml_error_code::invalid_string);
                --i; continue;
            }
            switch (e) {
            case 'b': c = '\b'; break; case 't': c = '\t'; break;
            case 'n': c = '\n'; break; case 'f': c = '\f'; break;
            case 'r': c = '\r'; break; case 'e': c = 27; break;
            case '"': c = '"'; break; case '\\': c = '\\'; break;
            case 'x': case 'u': case 'U': {
                unsigned count = e == 'x' ? 2 : e == 'u' ? 4 : 8; std::uint32_t cp = 0;
                if (s.size() - i - 1 < count) return fail(toml_error_code::invalid_string);
                for (unsigned j = 0; j < count; ++j) { int d = hex(s[++i]); if (d < 0) return fail(toml_error_code::invalid_string); cp = (cp << 4) | static_cast<unsigned>(d); }
                if (!unicode(cp)) return false;
                continue;
            }
            default: return fail(toml_error_code::invalid_string, t.offset + delim + i);
            }
        }
        if (decode && !put(static_cast<char>(c))) return false;
    }
    out = decode ? std::string_view(start ? strings.data() + start : strings.data(), chars - start) : s;
    return true;
}
bool parser::keys(std::array<std::string_view, max_depth>& path, std::size_t& count) {
    count = 0; bool need = true;
    while (!failed) {
        if (tok.kind == token_kind::basic_string || tok.kind == token_kind::literal_string) {
            if (!need) return fail(toml_error_code::invalid_syntax);
            if (count == max_depth) return fail(toml_error_code::nesting_limit);
            if (!string_value(tok, path[count++])) return false;
            need = false; advance();
        } else if (tok.kind == token_kind::atom) {
            auto s = tok.raw; std::size_t i = 0;
            while (i < s.size()) {
                if (!need) { if (s[i++] != '.') return fail(toml_error_code::invalid_syntax); need = true; continue; }
                auto start = i; while (i < s.size() && bare(s[i])) ++i;
                if (start == i) return fail(toml_error_code::invalid_syntax);
                if (count == max_depth) return fail(toml_error_code::nesting_limit);
                path[count++] = s.substr(start, i-start); need = false;
            }
            advance();
        } else break;
    }
    return (!need && count) || fail(toml_error_code::invalid_syntax);
}
toml_value* parser::descend(toml_value* p, std::string_view key, bool header) {
    auto* existing = const_cast<toml_value*>(p->find(key));
    if (!existing) {
        existing = node(toml_type::table); if (!existing) return nullptr;
        existing->key = key; existing->parser_flags = header ? 0 : dotted; append(p, existing); return existing;
    }
    if (existing->type == toml_type::array && (existing->parser_flags & array_tables) && header) return existing->last_child;
    if (existing->type != toml_type::table || (existing->parser_flags & sealed) || (!header && (existing->parser_flags & defined))) {
        fail(toml_error_code::conflicting_table); return nullptr;
    }
    if (!header) existing->parser_flags |= dotted;
    return existing;
}
bool parser::assignment(toml_value* table, std::size_t depth) {
    std::array<std::string_view, max_depth> path; std::size_t count;
    if (!keys(path, count) || !expect(token_kind::equals)) return false;
    if (depth + count > max_depth) return fail(toml_error_code::nesting_limit);
    for (std::size_t i = 0; i+1 < count; ++i) { table = descend(table, path[i], false); if (!table) return false; }
    if (table->find(path[count-1])) return fail(toml_error_code::duplicate_key);
    auto* p = node(toml_type::table); if (!p) return false;
    p->key = path[count-1]; append(table, p);
    return value(p, depth + count);
}
bool parser::value(toml_value* p, std::size_t depth) {
    if (depth > max_depth) return fail(toml_error_code::nesting_limit);
    if (accept(token_kind::left_bracket)) {
        p->type = toml_type::array; newlines();
        while (!failed && tok.kind != token_kind::right_bracket) {
            auto* child = node(toml_type::table); if (!child) return false; append(p, child);
            if (!value(child, depth+1)) return false;
            newlines();
            if (tok.kind == token_kind::right_bracket) break;
            if (!expect(token_kind::comma)) return false;
            newlines();
        }
        return expect(token_kind::right_bracket);
    }
    if (accept(token_kind::left_brace)) {
        p->type = toml_type::table; newlines();
        while (!failed && tok.kind != token_kind::right_brace) {
            if (!assignment(p, depth)) return false;
            newlines();
            if (tok.kind == token_kind::right_brace) break;
            if (!expect(token_kind::comma)) return false;
            newlines();
        }
        p->parser_flags |= sealed; return expect(token_kind::right_brace);
    }
    if (tok.kind == token_kind::basic_string || tok.kind == token_kind::literal_string ||
        tok.kind == token_kind::multiline_basic_string || tok.kind == token_kind::multiline_literal_string) {
        p->type = toml_type::string; if (!string_value(tok, p->string)) return false; advance(); return !failed;
    }
    if (tok.kind != token_kind::atom) return fail(toml_error_code::invalid_syntax);
    if (!scalar(p, tok.raw)) return false;
    advance();
    return !failed;
}
bool parser::datetime(toml_value* p, std::string_view s) {
    std::size_t i = 0; toml_datetime d;
    auto number = [&](unsigned n, int& out) {
        if (s.size() - i < n) return false;
        out = 0;
        for (unsigned j = 0; j < n; ++j) { if (!digit(s[i])) return false; out = out * 10 + s[i++] - '0'; }
        return true;
    };
    auto character = [&](char c) { if (i == s.size() || s[i] != c) return false; ++i; return true; };
    bool date = s.size() >= 10 && s[4] == '-';
    if (date) {
        if (!number(4, d.year) || !character('-') || !number(2, d.month) || !character('-') || !number(2, d.day)) return fail(toml_error_code::invalid_datetime);
        bool leap = d.year % 4 == 0 && (d.year % 100 != 0 || d.year % 400 == 0);
        constexpr int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
        if (d.month < 1 || d.month > 12 || d.day < 1 || d.day > days[d.month-1] + (d.month == 2 && leap)) return fail(toml_error_code::invalid_datetime);
        if (i == s.size()) { p->type = toml_type::local_date; p->datetime = d; return true; }
        if (s[i] != 'T' && s[i] != 't' && s[i] != ' ') return fail(toml_error_code::invalid_datetime);
        ++i;
    }
    if (!number(2, d.hour) || !character(':') || !number(2, d.minute)) return fail(toml_error_code::invalid_datetime);
    bool seconds = false;
    if (i < s.size() && s[i] == ':') { ++i; seconds = true; if (!number(2, d.second)) return fail(toml_error_code::invalid_datetime); }
    if (d.hour > 23 || d.minute > 59 || d.second > 60) return fail(toml_error_code::invalid_datetime);
    if (i < s.size() && s[i] == '.') {
        if (!seconds) return fail(toml_error_code::invalid_datetime);
        ++i; unsigned precision = 0;
        while (i < s.size() && digit(s[i])) { if (precision < 9) d.nanosecond = d.nanosecond * 10 + static_cast<unsigned>(s[i] - '0'); ++precision; ++i; }
        if (!precision) return fail(toml_error_code::invalid_datetime);
        for (; precision < 9; ++precision) d.nanosecond *= 10;
    }
    p->type = date ? toml_type::local_datetime : toml_type::local_time;
    if (date && i < s.size()) {
        p->type = toml_type::offset_datetime;
        if (s[i] == 'Z' || s[i] == 'z') ++i;
        else {
            if (s[i] != '+' && s[i] != '-') return fail(toml_error_code::invalid_datetime);
            int sign = s[i++] == '-' ? -1 : 1, hour, minute;
            if (!number(2, hour) || !character(':') || !number(2, minute) || hour > 23 || minute > 59) return fail(toml_error_code::invalid_datetime);
            d.offset_minutes = sign * (hour * 60 + minute);
        }
    }
    if (i != s.size()) return fail(toml_error_code::invalid_datetime);
    p->datetime = d; return true;
}
bool parser::scalar(toml_value* p, std::string_view s) {
    if (s == "true" || s == "false") { p->type = toml_type::boolean; p->boolean = s == "true"; return true; }
    if ((s.size() >= 10 && s[4] == '-') || (s.size() >= 5 && s[2] == ':')) return datetime(p, s);
    bool negative = false; std::size_t i = 0;
    if (!s.empty() && (s[0] == '+' || s[0] == '-')) { negative = s[0] == '-'; ++i; }
    auto rest = s.substr(i);
    if (rest == "inf" || rest == "nan") {
        p->type = toml_type::floating; p->floating = rest == "inf" ? std::numeric_limits<double>::infinity() : std::numeric_limits<double>::quiet_NaN();
        if (negative) p->floating = -p->floating;
        return true;
    }
    unsigned base = 10;
    if (i == 0 && s.size() > 2 && s[0] == '0') {
        if (s[1] == 'x') base = 16; else if (s[1] == 'o') base = 8; else if (s[1] == 'b') base = 2;
        if (base != 10) i = 2;
    }
    auto digits = [&](std::size_t& pos, unsigned radix) {
        auto start = pos; bool prev = false;
        while (pos < s.size()) {
            int d = hex(s[pos]);
            if (d >= 0 && static_cast<unsigned>(d) < radix) { prev = true; ++pos; }
            else if (s[pos] == '_') {
                if (!prev || pos+1 == s.size()) return false;
                int next = hex(s[pos+1]); if (next < 0 || static_cast<unsigned>(next) >= radix) return false;
                prev = false; ++pos;
            } else break;
        }
        return pos > start && prev;
    };
    auto integer_start = i;
    if (!digits(i, base)) return fail(toml_error_code::invalid_number);
    if (base == 10 && s[integer_start] == '0' && i-integer_start > 1) return fail(toml_error_code::invalid_number);
    bool floating = false;
    if (base == 10 && i < s.size() && s[i] == '.') { floating = true; ++i; if (!digits(i, 10)) return fail(toml_error_code::invalid_number); }
    if (base == 10 && i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        floating = true; ++i; if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
        if (!digits(i, 10)) return fail(toml_error_code::invalid_number);
    }
    if (i != s.size()) return fail(toml_error_code::invalid_number);
    if (!floating) {
        std::uint64_t v = 0, limit = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + (negative ? 1 : 0);
        for (i = integer_start; i < s.size(); ++i) {
            if (s[i] == '_') continue;
            auto d = static_cast<unsigned>(hex(s[i]));
            if (v > (limit-d)/base) return fail(toml_error_code::invalid_number);
            v = v*base+d;
        }
        p->type = toml_type::integer;
        p->integer = negative ? (v == limit ? std::numeric_limits<std::int64_t>::min() : -static_cast<std::int64_t>(v)) : static_cast<std::int64_t>(v);
        return true;
    }
    // A bounded significant-digit spelling covers every binary64 midpoint.
    // Discarded digits are represented by a sticky nonzero digit, preserving
    // rounding even for arbitrarily long decimal spellings.
    std::array<char, 1152> normalized{}; std::size_t length = 0;
    if (negative) normalized[length++] = '-';
    std::size_t pos = (s[0] == '+' || s[0] == '-') ? 1 : 0;
    long long exponent = 0; bool dot = false, significant = false, sticky = false;
    std::size_t significant_count = 0;
    for (; pos < s.size() && s[pos] != 'e' && s[pos] != 'E'; ++pos) {
        char c = s[pos]; if (c == '_') continue; if (c == '.') { dot = true; continue; }
        if (dot && exponent > -1000000000) --exponent;
        if (c == '0' && !significant) continue;
        significant = true;
        if (significant_count < 1100) { normalized[length++] = c; ++significant_count; }
        else { if (exponent < 1000000000) ++exponent; sticky |= c != '0'; }
    }
    if (!significant) { p->type = toml_type::floating; p->floating = negative ? -0.0 : 0.0; return true; }
    if (sticky) { normalized[length++] = '1'; --exponent; }
    if (pos < s.size()) {
        ++pos; bool neg_exp = false;
        if (s[pos] == '+' || s[pos] == '-') neg_exp = s[pos++] == '-';
        long long explicit_exp = 0;
        for (; pos < s.size(); ++pos) if (s[pos] != '_') { if (explicit_exp < 1000000000) explicit_exp = explicit_exp * 10 + s[pos] - '0'; }
        exponent += neg_exp ? -explicit_exp : explicit_exp;
    }
    normalized[length++] = 'e';
    auto result = std::to_chars(normalized.data()+length, normalized.data()+normalized.size(), exponent);
    length = static_cast<std::size_t>(result.ptr-normalized.data());
    double number{};
    auto converted = std::from_chars(normalized.data(), normalized.data()+length, number);
    if (converted.ec == std::errc::result_out_of_range) {
        // Underflow preserves signed zero; finite spelling overflow is an error.
        if (exponent + static_cast<long long>(significant_count) < -323) number = negative ? -0.0 : 0.0;
        else return fail(toml_error_code::invalid_number);
    } else if (converted.ec != std::errc{}) return fail(toml_error_code::invalid_number);
    p->type = toml_type::floating; p->floating = number; return true;
}
auto parser::run() -> std::expected<toml_document, toml_error> {
    if (!utf8()) return std::unexpected(error);
    advance();
    if (failed) return std::unexpected(error);
    auto* root = node(toml_type::table); if (!root) return std::unexpected(error);
    root->parser_flags = defined; auto* current = root; std::size_t table_depth = 0;
    newlines();
    while (!failed && tok.kind != token_kind::end) {
        if (tok.kind == token_kind::left_bracket) {
            auto opening_offset = tok.offset;
            advance();
            bool aot = tok.kind == token_kind::left_bracket;
            if (aot) {
                if (tok.offset != opening_offset + 1) { fail(toml_error_code::invalid_syntax); break; }
                advance();
            }
            std::array<std::string_view, max_depth> path; std::size_t count;
            if (!keys(path, count)) break;
            auto closing_offset = tok.offset;
            if (!expect(token_kind::right_bracket)) break;
            if (aot) {
                if (tok.offset != closing_offset + 1) { fail(toml_error_code::invalid_syntax); break; }
                if (!expect(token_kind::right_bracket)) break;
            }
            auto* parent = root;
            for (std::size_t i = 0; i+1 < count && parent; ++i) parent = descend(parent, path[i], true);
            if (!parent) break;
            auto* p = const_cast<toml_value*>(parent->find(path[count-1]));
            if (aot) {
                if (!p) { p = node(toml_type::array); if (!p) break; p->key = path[count-1]; p->parser_flags = array_tables; append(parent,p); }
                if (p->type != toml_type::array || !(p->parser_flags & array_tables)) { fail(toml_error_code::conflicting_table); break; }
                current = node(toml_type::table); if (!current) break; current->parser_flags = defined; append(p,current);
            } else {
                if (!p) { p = node(toml_type::table); if (!p) break; p->key = path[count-1]; append(parent,p); }
                if (p->type != toml_type::table || p->parser_flags) { fail(toml_error_code::conflicting_table); break; }
                p->parser_flags = defined; current = p;
            }
            table_depth = count;
        } else if (!assignment(current, table_depth)) break;
        if (tok.kind != token_kind::newline && tok.kind != token_kind::end) { fail(toml_error_code::invalid_syntax); break; }
        newlines();
    }
    if (failed) return std::unexpected(error);
    return toml_document(root, used, chars);
}
} // namespace

auto parse_toml(std::string_view input, std::span<toml_value> nodes,
    std::span<char> decoded_strings) noexcept -> std::expected<toml_document, toml_error> {
    return parser(input, nodes, decoded_strings).run();
}
} // namespace stonegate
