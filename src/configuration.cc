#include "configuration.h"

#include "toml.h"

#include "eventloop/ip_endpoint.h"
#include "eventloop/util/arg_parser.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace stonegate {
namespace {

constexpr std::string_view usage =
    "Stonegate: bounded static HTTP server\n"
    "usage: stonegate --root DIR [options] | --config FILE [options]\n"
    "  --config FILE           load TOML settings before CLI options\n"
    "  --server NAME           select server for CLI overrides\n"
    "  --check                 validate config and credentials, then exit\n"
    "  --bind ADDRESS          numeric IPv4/IPv6 bind address (default 127.0.0.1)\n"
    "  --http-port PORT        plain HTTP port (default 8080)\n"
    "  --http-mode MODE        serve, redirect, or off (default serve)\n"
    "  --https-port PORT       TLS port (default 8443; 0 disables)\n"
    "  --http3-port PORT       UDP HTTP/3 port (0 disables; default off)\n"
    "  --http3-connections N  concurrent HTTP/3 connections (1..256; default 8)\n"
    "  --http3-requests N     concurrent HTTP/3 requests (0..8192; 0 selects 10 per connection)\n"
    "  --http3-max-datagram N max application UDP payload 1200..8192 (default 8192)\n"
    "  --certificate FILE      PEM certificate chain\n"
    "  --private-key FILE      PEM private key\n"
    "  --key-password TEXT     password for encrypted private key\n"
    "  --redirect-host HOST    host in HTTP to HTTPS redirect (default localhost)\n"
    "  --http2 on|off         TLS HTTP/2 ALPN (default on)\n"
    "  --server-name HOST      host name this server answers (repeatable)\n"
    "  --directory-listing     list directories without index files\n"
    "  --no-directory-listing  disable directory listing\n"
    "  --precompressed         serve FILE.br/FILE.gz to clients accepting them\n"
    "  --no-precompressed      disable precompressed files\n"
    "  --gzip                  gzip compressible files while sending\n"
    "  --no-gzip               disable on-the-fly gzip\n"
    "  --gzip-min-size N       smallest file to gzip (default 1024)\n"
    "  --gzip-max-size N       largest file to gzip (default 8388608)\n"
    "  --access-log FILE       append access log lines to FILE (- for stdout)\n"
    "  --real-ip-header NAME   log the first address of this request field\n"
    "  --reuse-port            allow multiple listeners to reuse a port\n"
    "  --no-reuse-port         disable port reuse\n"
    "  --shutdown-seconds N    in-flight request drain deadline (default 5)\n"
    "  --workers N             event-loop threads serving every listener (1..256; default 1)\n"
    "  --worker-mode MODE      auto, reuse_port, or handoff (default auto)\n"
    "  --user NAME             switch to this user once listeners are open\n"
    "  --group NAME            switch to this group (default: the user's group)\n"
    "  --header-timeout-ms N    first head/TLS timeout (0..3600000)\n"
    "  --idle-timeout-ms N      next head timeout (0..3600000)\n"
    "  --help                  show this message\n";

auto parse_worker_mode(std::string_view value) -> worker_mode
{
    if (value == "auto") return worker_mode::automatic;
    if (value == "reuse_port") return worker_mode::reuse_port;
    if (value == "handoff") return worker_mode::handoff;
    throw std::invalid_argument("worker_mode must be auto, reuse_port, or handoff");
}

template<typename T>
auto number(std::string_view text, std::string_view name, T minimum, T maximum) -> T
{
    T result {};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc {} || end != text.data() + text.size() ||
        result < minimum || result > maximum) {
        throw std::invalid_argument(std::string(name) + " has an invalid value");
    }
    return result;
}

auto on_off(std::string_view value, std::string_view name) -> bool
{
    if (value == "on") return true;
    if (value == "off") return false;
    throw std::invalid_argument(std::string(name) + " must be on or off");
}

[[nodiscard]] auto lowercase_token(std::string_view name) -> bool
{
    return !name.empty() && name.size() <= 64 &&
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~") ==
            std::string_view::npos;
}

// Visible ASCII with inner spaces or tabs, so a value cannot split a field.
[[nodiscard]] auto field_value(std::string_view value) -> bool
{
    return !value.empty() && value.size() <= 1024 && value.front() != ' ' &&
        value.front() != '\t' && value.back() != ' ' && value.back() != '\t' &&
        std::ranges::all_of(value, [](unsigned char byte) {
            return byte == '\t' || (byte >= 0x20 && byte != 0x7f);
        });
}

[[nodiscard]] auto host_name(std::string_view name) -> bool
{
    if (name.starts_with("*.")) name.remove_prefix(2);
    if (name.empty() || name.size() > 253 || name.front() == '.' || name.back() == '.' ||
        name.contains(".."))
        return false;
    return name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-.") ==
        std::string_view::npos;
}

[[nodiscard]] auto url_path(std::string_view path) -> bool
{
    return path.starts_with('/') && path.size() <= 1024 &&
        path.find_first_of("?#\\") == std::string_view::npos &&
        std::ranges::all_of(path, [](unsigned char byte) { return byte > 0x20 && byte != 0x7f; });
}

// Fields Stonegate sets itself, plus fields HTTP/2 and HTTP/3 forbid.
constexpr std::string_view reserved_headers[] {
    "accept-ranges", "allow", "alt-svc", "cache-control", "connection", "content-encoding",
    "content-length", "content-range", "content-type", "date", "etag", "keep-alive",
    "last-modified", "location", "proxy-connection", "te", "transfer-encoding", "upgrade",
    "vary",
};

constexpr unsigned error_page_statuses[] {400, 403, 404, 405, 414, 500};

auto add_header(server_config& settings, std::string_view name, std::string_view value) -> void
{
    if (!lowercase_token(name) || std::ranges::contains(reserved_headers, name))
        throw std::invalid_argument("header name must be a lowercase field Stonegate does not set");
    if (!field_value(value)) throw std::invalid_argument("header value is invalid");
    const auto existing = std::ranges::find(settings.headers, name,
        &std::pair<std::string, std::string>::first);
    if (existing != settings.headers.end()) existing->second = value;
    else if (settings.headers.size() == max_response_headers)
        throw std::invalid_argument("header capacity exhausted (32)");
    else settings.headers.emplace_back(name, value);
}

auto add_cache_rule(server_config& settings, std::string_view pattern, std::string_view value) -> void
{
    const bool suffix = pattern.starts_with("*.") && pattern.size() > 2 && pattern.size() <= 32 &&
        pattern.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-",
                                  2) == std::string_view::npos;
    if (!suffix && !url_path(pattern))
        throw std::invalid_argument("cache_control pattern must be a /prefix or *.extension");
    if (!field_value(value)) throw std::invalid_argument("cache_control value is invalid");
    const auto existing = std::ranges::find(settings.cache_rules, pattern, &cache_rule::pattern);
    if (existing != settings.cache_rules.end()) existing->value = value;
    else if (settings.cache_rules.size() == max_cache_rules)
        throw std::invalid_argument("cache_control capacity exhausted (64)");
    else settings.cache_rules.push_back({std::string(pattern), std::string(value)});
}

auto add_error_page(server_config& settings, std::string_view status_text, std::string_view path) -> void
{
    unsigned status = 0;
    const auto [end, error] = std::from_chars(status_text.data(),
        status_text.data() + status_text.size(), status);
    if (error != std::errc {} || end != status_text.data() + status_text.size() ||
        !std::ranges::contains(error_page_statuses, status))
        throw std::invalid_argument("error_pages status must be 400, 403, 404, 405, 414, or 500");
    if (!url_path(path)) throw std::invalid_argument("error page must be a document-root path");
    const auto existing = std::ranges::find(settings.error_pages, status,
        &std::pair<unsigned, std::string>::first);
    if (existing != settings.error_pages.end()) existing->second = path;
    else settings.error_pages.emplace_back(status, path);
}

auto apply(server_config& settings, std::string_view key, std::string_view value,
           const std::filesystem::path* config_dir = nullptr) -> void
{
    const auto path_value = [&] {
        if (value.empty()) return std::string {};
        const std::filesystem::path path {value};
        return (config_dir != nullptr && path.is_relative()
            ? (*config_dir / path).lexically_normal() : path).string();
    };
    if (value.empty() && key != "certificate" && key != "private-key" &&
        key != "key-password" && key != "access-log" && key != "real-ip-header")
        throw std::invalid_argument(std::string(key) + " has an empty value");
    if (key == "root") settings.root = path_value();
    else if (key == "bind") settings.bind = value;
    else if (key == "certificate") settings.certificate = path_value();
    else if (key == "private-key") settings.private_key = path_value();
    else if (key == "key-password") settings.key_password = value;
    else if (key == "redirect-host") settings.redirect_host = value;
    else if (key == "http-port") settings.http_port = number<std::uint16_t>(value, key, 1, 65535);
    else if (key == "https-port") settings.https_port = number<std::uint16_t>(value, key, 0, 65535);
    else if (key == "http3-port") settings.http3_port = number<std::uint16_t>(value, key, 0, 65535);
    else if (key == "http3-connections") settings.http3_connections = number<std::size_t>(value, key, 1, 256);
    else if (key == "http3-requests") settings.http3_requests = number<std::size_t>(value, key, 0, 8192);
    else if (key == "http3-max-datagram")
        settings.http3_max_datagram = number<std::size_t>(value, key, 1200, 8192);
    else if (key == "header-timeout-ms")
        settings.header_timeout_ms = number<int>(value, key, 0, 3600000);
    else if (key == "idle-timeout-ms")
        settings.idle_timeout_ms = number<int>(value, key, 0, 3600000);
    else if (key == "http-mode") {
            if (value == "serve") settings.mode = server_config::http_mode::serve;
            else if (value == "redirect") settings.mode = server_config::http_mode::redirect;
            else if (value == "off") settings.mode = server_config::http_mode::off;
            else throw std::invalid_argument("http-mode must be serve, redirect, or off");
    } else if (key == "http2") settings.http2 = on_off(value, key);
    else if (key == "directory-listing") settings.directory_listing = on_off(value, key);
    else if (key == "reuse-port") settings.reuse_port = on_off(value, key);
    else if (key == "server-name") {
        if (!host_name(value))
            throw std::invalid_argument("server-name must be a lowercase host name or *.domain");
        if (settings.server_names.size() == max_server_names)
            throw std::invalid_argument("server-name capacity exhausted (16)");
        settings.server_names.emplace_back(value);
    } else if (key == "access-log") settings.access_log = value == "-" ? "-" : path_value();
    else if (key == "real-ip-header") {
        if (!value.empty() && !lowercase_token(value))
            throw std::invalid_argument("real-ip-header must be a lowercase field name");
        settings.real_ip_header = value;
    } else if (key == "precompressed") settings.precompressed = on_off(value, key);
    else if (key == "gzip") settings.gzip = on_off(value, key);
    else if (key == "gzip-min-size")
        settings.gzip_min_size = number<std::uint64_t>(value, key, 0, std::uint64_t {1} << 30);
    else if (key == "gzip-max-size")
        settings.gzip_max_size = number<std::uint64_t>(value, key, 0, std::uint64_t {1} << 30);
    else throw std::invalid_argument("unknown setting");
}

struct setting {
    std::string_view section, key, cli;
    toml_type type;
};
constexpr setting schema[] {
    {"", "root", "root", toml_type::string},
    {"", "bind", "bind", toml_type::string},
    {"", "directory_listing", "directory-listing", toml_type::boolean},
    {"", "reuse_port", "reuse-port", toml_type::boolean},
    {"", "header_timeout_ms", "header-timeout-ms", toml_type::integer},
    {"", "idle_timeout_ms", "idle-timeout-ms", toml_type::integer},
    {"", "access_log", "access-log", toml_type::string},
    {"", "real_ip_header", "real-ip-header", toml_type::string},
    {"http", "mode", "http-mode", toml_type::string},
    {"http", "port", "http-port", toml_type::integer},
    {"http", "redirect_host", "redirect-host", toml_type::string},
    {"tls", "port", "https-port", toml_type::integer},
    {"tls", "certificate", "certificate", toml_type::string},
    {"tls", "private_key", "private-key", toml_type::string},
    {"tls", "key_password", "key-password", toml_type::string},
    {"tls", "http2", "http2", toml_type::boolean},
    {"http3", "port", "http3-port", toml_type::integer},
    {"http3", "connections", "http3-connections", toml_type::integer},
    {"http3", "requests", "http3-requests", toml_type::integer},
    {"http3", "max_datagram", "http3-max-datagram", toml_type::integer},
    {"compression", "precompressed", "precompressed", toml_type::boolean},
    {"compression", "gzip", "gzip", toml_type::boolean},
    {"compression", "gzip_min_size", "gzip-min-size", toml_type::integer},
    {"compression", "gzip_max_size", "gzip-max-size", toml_type::integer},
};
// Boolean settings that the CLI spells as --NAME and --no-NAME.
constexpr std::string_view flag_settings[] {
    "directory-listing", "reuse-port", "precompressed", "gzip",
};

auto require_type(const toml_value& value, toml_type type,
                  std::string_view location = {}) -> void
{
    if (value.type != type)
        throw std::invalid_argument((location.empty() ? std::string {} :
            std::string(location) + ": ") + "wrong TOML type");
}

auto text(const toml_value& value) -> std::string_view
{
    require_type(value, toml_type::string);
    if (value.string.contains('\0'))
        throw std::invalid_argument("string contains NUL");
    return value.string;
}

// Reads a table of string values, such as headers, into add(key, value).
template<typename Add>
auto read_string_table(const toml_value& table, const std::string& location, Add add) -> void
{
    require_type(table, toml_type::table, location);
    for (const auto& value : table) {
        try { add(value.key, text(value)); }
        catch (const std::invalid_argument& error) {
            throw std::invalid_argument(location + "." + std::string(value.key) + ": " +
                                        error.what());
        }
    }
}

auto read_server(server_config& settings, const toml_value& table,
                 const std::filesystem::path& directory,
                 const std::string& prefix, std::string_view section = {}) -> void
{
    require_type(table, toml_type::table, prefix);
    for (const auto& value : table) {
        const auto location = prefix + "." + std::string(value.key);
        if (section.empty() && (value.key == "http" || value.key == "tls" ||
                                value.key == "http3" || value.key == "compression")) {
            read_server(settings, value, directory, location, value.key);
            continue;
        }
        if (section.empty() && value.key == "headers") {
            read_string_table(value, location, [&](std::string_view name, std::string_view field) {
                add_header(settings, name, field);
            });
            continue;
        }
        if (section.empty() && value.key == "cache_control") {
            read_string_table(value, location, [&](std::string_view pattern, std::string_view field) {
                add_cache_rule(settings, pattern, field);
            });
            continue;
        }
        if (section.empty() && value.key == "error_pages") {
            read_string_table(value, location, [&](std::string_view status, std::string_view path) {
                add_error_page(settings, status, path);
            });
            continue;
        }
        try {
            if (section.empty() && value.key == "name" && prefix.starts_with("server[")) {
                settings.name = text(value);
                if (settings.name.empty() || settings.name.size() > 64 ||
                    settings.name.find_first_not_of(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos)
                    throw std::invalid_argument("invalid server name");
                continue;
            }
            if (section.empty() && value.key == "server_names") {
                require_type(value, toml_type::array);
                settings.server_names.clear();
                for (const auto& entry : value) apply(settings, "server-name", text(entry));
                continue;
            }
            const auto entry = std::ranges::find_if(schema,
                [&](const auto& item) { return item.section == section && item.key == value.key; });
            if (entry == std::ranges::end(schema)) throw std::invalid_argument("unknown setting");
            require_type(value, entry->type);
            if (value.type == toml_type::string) apply(settings, entry->cli, text(value), &directory);
            else if (value.type == toml_type::boolean)
                apply(settings, entry->cli, value.boolean ? "on" : "off");
            else apply(settings, entry->cli, std::to_string(value.integer));
        } catch (const std::invalid_argument& error) {
            throw std::invalid_argument(location + ": " + error.what());
        }
    }
}

auto toml_error_name(toml_error_code code) -> std::string_view
{
    using enum toml_error_code;
    switch (code) {
    case invalid_syntax: return "invalid syntax";
    case invalid_utf8: return "invalid UTF-8";
    case invalid_string: return "invalid string";
    case invalid_number: return "invalid number";
    case invalid_datetime: return "invalid date/time";
    case duplicate_key: return "duplicate key";
    case conflicting_table: return "conflicting table";
    case node_capacity: return "TOML node capacity exhausted (2048)";
    case string_capacity: return "TOML string capacity exhausted (64 KiB)";
    case nesting_limit: return "TOML nesting limit exceeded";
    }
    return "invalid TOML";
}

auto account_name(std::string_view name, std::string_view setting) -> std::string
{
    if (name.empty() || name.size() > 64 ||
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") !=
            std::string_view::npos)
        throw std::invalid_argument(std::string(setting) + " must be an account name");
    return std::string(name);
}

class config_loader {
public:
    explicit config_loader(configuration& output) : output_(output) {}
    auto load(const std::filesystem::path& path, std::size_t depth = 1) -> void
    {
        try { load_file(path, depth); }
        catch (const std::exception& error) {
            throw std::invalid_argument(path.string() + ": " + error.what());
        }
    }
    server_config defaults;
private:
    configuration& output_;
    std::set<std::filesystem::path> seen_;
    std::size_t total_bytes_ = 0;

    auto read_runtime(const toml_value& table) -> void
    {
        require_type(table, toml_type::table, "runtime");
        for (const auto& value : table) {
            if (value.key == "shutdown_seconds") {
                require_type(value, toml_type::integer, "runtime.shutdown_seconds");
                output_.shutdown_seconds = number<int>(std::to_string(value.integer),
                    "runtime.shutdown_seconds", 0, 3600);
            } else if (value.key == "workers") {
                require_type(value, toml_type::integer, "runtime.workers");
                output_.workers = number<std::size_t>(std::to_string(value.integer),
                    "runtime.workers", 1, max_workers);
            } else if (value.key == "worker_mode") {
                require_type(value, toml_type::string, "runtime.worker_mode");
                output_.mode = parse_worker_mode(text(value));
            } else if (value.key == "user") {
                require_type(value, toml_type::string, "runtime.user");
                output_.user = account_name(text(value), "runtime.user");
            } else if (value.key == "group") {
                require_type(value, toml_type::string, "runtime.group");
                output_.group = account_name(text(value), "runtime.group");
            } else throw std::invalid_argument("runtime: unknown setting");
        }
    }

    auto load_file(const std::filesystem::path& path, std::size_t depth) -> void
    {
        if (depth > 8) throw std::invalid_argument("include depth exceeds 8");
        if (seen_.size() == 32) throw std::invalid_argument("config file capacity exhausted (32)");
        std::error_code error;
        const auto canonical = std::filesystem::canonical(path, error);
        if (error) throw std::invalid_argument("cannot open config file");
        if (!seen_.insert(canonical).second)
            throw std::invalid_argument("repeated or cyclic include");
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::invalid_argument("cannot open config file");
        constexpr std::size_t max_bytes = 64 * 1024;
        std::string input(max_bytes + 1, '\0');
        file.read(input.data(), static_cast<std::streamsize>(input.size()));
        if (file.bad()) throw std::invalid_argument("error reading config file");
        input.resize(static_cast<std::size_t>(file.gcount()));
        if (input.size() > max_bytes) throw std::invalid_argument("config file exceeds 64 KiB");
        total_bytes_ += input.size();
        if (total_bytes_ > 1024 * 1024) throw std::invalid_argument("combined config exceeds 1 MiB");
        // Heap-backed setup buffers avoid large per-include stack frames.
        auto nodes = std::make_unique<toml_value[]>(2048);
        auto strings = std::make_unique<char[]>(max_bytes);
        const auto document = parse_toml(input,
            std::span(nodes.get(), 2048), std::span(strings.get(), max_bytes));
        if (!document) {
            const auto offset = std::min(document.error().offset, input.size());
            const auto before = std::string_view(input).substr(0, offset);
            const auto line = 1 + std::count(before.begin(), before.end(), '\n');
            const auto newline = before.rfind('\n');
            const auto column = newline == std::string_view::npos ? offset + 1 : offset - newline;
            throw std::invalid_argument("line " + std::to_string(line) + ", column " +
                std::to_string(column) + ": " + std::string(toml_error_name(document.error().code)));
        }
        const auto& root = document->root();
        for (const auto& value : root) {
            if (value.key != "include" && value.key != "server" &&
                !(depth == 1 && (value.key == "defaults" || value.key == "runtime")))
                throw std::invalid_argument("unknown top-level setting or setting forbidden in include");
        }
        const auto directory = path.parent_path();
        if (const auto* table = root.find("defaults"))
            read_server(defaults, *table, directory, "defaults");
        if (const auto* table = root.find("runtime")) read_runtime(*table);
        if (const auto* includes = root.find("include")) {
            require_type(*includes, toml_type::array, "include");
            for (const auto& entry : *includes) {
                require_type(entry, toml_type::string, "include[]");
                const auto name = text(entry);
                if (name.empty()) throw std::invalid_argument("empty include path");
                const std::filesystem::path included {name};
                load(included.is_absolute() ? included : directory / included, depth + 1);
            }
        }
        if (const auto* servers = root.find("server")) {
            require_type(*servers, toml_type::array, "server");
            for (const auto& table : *servers) {
                if (output_.servers.size() == max_servers)
                    throw std::invalid_argument("server capacity exhausted (16)");
                auto settings = defaults;
                read_server(settings, table, directory,
                    "server[" + std::to_string(output_.servers.size() + 1) + "]");
                output_.servers.push_back(std::move(settings));
            }
        }
    }
};

auto validate(const server_config& settings) -> void
{
    std::error_code root_error;
    if (settings.root.empty() || !std::filesystem::is_directory(settings.root, root_error))
        throw std::invalid_argument("root must name an existing directory");
    const bool tls = !settings.certificate.empty() && !settings.private_key.empty();
    if (settings.certificate.empty() != settings.private_key.empty())
        throw std::invalid_argument("certificate and private-key must be supplied together");
    if (!settings.key_password.empty() && !tls)
        throw std::invalid_argument("key-password requires TLS credentials");
    if (settings.http3_port != 0 && !tls)
        throw std::invalid_argument("http3-port requires certificate and private-key");
    if (settings.mode == server_config::http_mode::redirect && (!tls || settings.https_port == 0))
        throw std::invalid_argument("TLS credentials and a TLS port are required for redirect");
    if (settings.mode == server_config::http_mode::off &&
        !(tls && (settings.https_port != 0 || settings.http3_port != 0)))
        throw std::invalid_argument("HTTP-off requires a TLS or HTTP/3 listener");
    if (settings.redirect_host.empty() ||
        std::any_of(settings.redirect_host.begin(), settings.redirect_host.end(),
            [](unsigned char byte) { return byte <= 32 || byte == 127; }) ||
        settings.redirect_host.find_first_of("/\\@?#") != std::string::npos)
        throw std::invalid_argument("redirect-host must be a hostname without whitespace or URL syntax");
    if (settings.gzip && !gzip_available)
        throw std::invalid_argument("gzip needs a Stonegate build with zlib");
    if (settings.gzip_min_size > settings.gzip_max_size)
        throw std::invalid_argument("gzip-min-size exceeds gzip-max-size");
    if (!settings.access_log.empty() && settings.access_log != "-") {
        const auto parent = std::filesystem::path(settings.access_log).parent_path();
        std::error_code log_error;
        if (!parent.empty() && !std::filesystem::is_directory(parent, log_error))
            throw std::invalid_argument("access-log directory does not exist");
    }
    (void)eventloop::ip_endpoint::parse(settings.bind, 0);
}

// Servers on overlapping endpoints must share every listener, and then pick
// their server by host name: names are unique among them, and at most one
// omits server_names to take the remaining hosts.
auto validate_endpoints(const std::vector<server_config>& servers) -> void
{
    struct listener { eventloop::ip_endpoint address; bool udp; std::size_t server; };
    std::vector<listener> listeners;
    const auto wildcard = [](const auto& endpoint) {
        return std::all_of(endpoint.address.begin(), endpoint.address.end(),
            [](auto byte) { return byte == 0; });
    };
    const auto add = [&](std::size_t index, std::uint16_t port, bool udp) {
        const auto address = eventloop::ip_endpoint::parse(servers[index].bind, port);
        for (const auto& other : listeners) {
            if (other.udp != udp || other.address.port != port ||
                other.address.address_family != address.address_family ||
                !(wildcard(address) || wildcard(other.address) ||
                  (other.address.address == address.address &&
                   other.address.scope_id == address.scope_id)))
                continue;
            const auto& left = servers[other.server];
            const auto& right = servers[index];
            if (other.server == index || !same_listeners(left, right))
                throw std::invalid_argument("overlapping listening endpoints");
            if (left.server_names.empty() && right.server_names.empty())
                throw std::invalid_argument("overlapping listening endpoints: servers sharing "
                                            "listeners need distinct server_names");
            for (const auto& name : right.server_names)
                if (std::ranges::contains(left.server_names, name))
                    throw std::invalid_argument("server name " + name +
                                                " repeats on shared listeners");
        }
        listeners.push_back({address, udp, index});
    };
    for (std::size_t index = 0; index < servers.size(); ++index) {
        const auto& server = servers[index];
        if (server.mode != server_config::http_mode::off) add(index, server.http_port, false);
        if (!server.certificate.empty() && server.https_port != 0) add(index, server.https_port, false);
        if (server.http3_port != 0) add(index, server.http3_port, true);
    }
}

} // namespace

auto same_listeners(const server_config& left, const server_config& right) -> bool
{
    return left.bind == right.bind && left.mode == right.mode &&
        left.http_port == right.http_port && left.https_port == right.https_port &&
        left.http3_port == right.http3_port && left.certificate == right.certificate &&
        left.private_key == right.private_key && left.key_password == right.key_password &&
        left.redirect_host == right.redirect_host && left.http2 == right.http2 &&
        left.reuse_port == right.reuse_port && left.http3_connections == right.http3_connections &&
        left.http3_requests == right.http3_requests &&
        left.http3_max_datagram == right.http3_max_datagram &&
        left.header_timeout_ms == right.header_timeout_ms &&
        left.idle_timeout_ms == right.idle_timeout_ms;
}

auto parse_configuration(int argc, char** argv) -> configuration
{
    struct override_entry { std::string_view key, value; };
    std::vector<override_entry> overrides;
    std::string_view config_path, selected_server;
    configuration output;
    const auto override_flag = [&overrides](std::string_view key, std::string_view value) {
        return eventloop::arg_parser::flag_handler([&overrides, key, value] {
            overrides.push_back({key, value});
        });
    };
    const auto override_value = [&overrides](std::string_view key) {
        return eventloop::arg_parser::value_handler([&overrides, key](std::string_view value) {
            overrides.push_back({key, value});
        });
    };
    const auto single = [](std::string_view& destination, std::string_view name) {
        return eventloop::arg_parser::value_handler([&destination, name](std::string_view value) {
            if (!destination.empty()) throw std::invalid_argument("duplicate --" + std::string(name));
            if (value.empty()) throw std::invalid_argument("empty value for --" + std::string(name));
            destination = value;
        });
    };
    using option = eventloop::arg_parser::option;
    std::vector<option> options {
        option {'\0', "check", &output.check, false},
        option {'\0', "config", single(config_path, "config"), false},
        option {'\0', "server", single(selected_server, "server"), false},
    };
    // --no-NAME spellings live in static storage because options borrow names.
    static const std::array<std::string, std::size(flag_settings)> negated = [] {
        std::array<std::string, std::size(flag_settings)> names;
        for (std::size_t index = 0; index < names.size(); ++index)
            names[index] = "no-" + std::string(flag_settings[index]);
        return names;
    }();
    for (std::size_t index = 0; index < std::size(flag_settings); ++index) {
        options.push_back({'\0', flag_settings[index], override_flag(flag_settings[index], "on"), false});
        options.push_back({'\0', negated[index], override_flag(flag_settings[index], "off"), false});
    }
    for (const auto key : {std::string_view("shutdown-seconds"), std::string_view("workers"),
                           std::string_view("worker-mode"), std::string_view("user"),
                           std::string_view("group"), std::string_view("server-name")})
        options.push_back({'\0', key, override_value(key), false});
    for (const auto& entry : schema)
        if (!std::ranges::contains(flag_settings, entry.cli))
            options.push_back({'\0', entry.cli, override_value(entry.cli), false});
    eventloop::arg_parser parser(options);
    parser.set_usage(usage);
    parser.parse(argc, argv);
    if (!config_path.empty()) {
        config_loader loader(output);
        loader.load(std::filesystem::path(config_path));
        if (output.servers.empty()) output.servers.push_back(std::move(loader.defaults));
    } else output.servers.emplace_back();
    std::set<std::string> names;
    for (std::size_t index = 0; index < output.servers.size(); ++index) {
        auto& name = output.servers[index].name;
        if (name.empty()) name = "server-" + std::to_string(index + 1);
        if (!names.insert(name).second) throw std::invalid_argument("duplicate server name");
    }
    auto* target = &output.servers.front();
    if (!selected_server.empty()) {
        const auto selected = std::ranges::find_if(output.servers,
            [&](const auto& server) { return server.name == selected_server; });
        if (selected == output.servers.end()) throw std::invalid_argument("unknown --server name");
        target = &*selected;
    }
    for (const auto& entry : overrides) {
        if (entry.key == "shutdown-seconds") {
            output.shutdown_seconds = number<int>(entry.value, entry.key, 0, 3600);
            continue;
        }
        if (entry.key == "workers") {
            output.workers = number<std::size_t>(entry.value, entry.key, 1, max_workers);
            continue;
        }
        if (entry.key == "worker-mode") {
            output.mode = parse_worker_mode(entry.value);
            continue;
        }
        if (entry.key == "user" || entry.key == "group") {
            (entry.key == "user" ? output.user : output.group) = account_name(entry.value, entry.key);
            continue;
        }
        if (output.servers.size() > 1 && selected_server.empty())
            throw std::invalid_argument("server CLI overrides require --server NAME with multiple servers");
        apply(*target, entry.key, entry.value);
    }
    if (!output.group.empty() && output.user.empty())
        throw std::invalid_argument("group requires user");
    for (const auto& server : output.servers) {
        try { validate(server); }
        catch (const std::exception& error) {
            throw std::invalid_argument("server " + server.name + ": " + error.what());
        }
    }
    validate_endpoints(output.servers);
    if (output.mode == worker_mode::automatic)
        output.mode = kernel_balances_reuse_port ? worker_mode::reuse_port : worker_mode::handoff;
    if (output.workers > 1 && output.mode == worker_mode::reuse_port &&
        !kernel_balances_reuse_port)
        throw std::invalid_argument("worker_mode reuse_port needs a kernel that balances "
                                    "shared ports (Linux); use handoff");
    return output;
}

} // namespace stonegate
