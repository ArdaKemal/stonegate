#include "static_files.h"

#include "access_log.h"
#include "file_response.h"

#include "eventloop/http/mime_types.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef STONEGATE_ZLIB
#include <zlib.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <expected>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace stonegate {
namespace {

using eventloop::http::header;
using eventloop::http::method_type;
using eventloop::unique_fd;

constexpr std::size_t max_decoded_path = 4096;
constexpr std::size_t listing_max_entries = 4096;
constexpr std::size_t listing_max_bytes = 1u << 20;
constexpr std::uint64_t max_error_page = 1u << 20;
constexpr std::uint64_t inline_body_limit = 16 * 1024;
constexpr std::string_view allowed_methods = "GET, HEAD, OPTIONS";

thread_local std::size_t active = 0;

// Counts a request from handler start to completion or destruction.
struct request_scope {
    std::chrono::steady_clock::time_point start {std::chrono::steady_clock::now()};
    request_scope() noexcept { ++active; }
    ~request_scope() { --active; }
    request_scope(const request_scope&) = delete;
    auto operator=(const request_scope&) -> request_scope& = delete;
};

// A response decided before any I/O: a file slice, a file to gzip, or an
// in-memory body.
struct reply {
    unsigned status {200};
    std::vector<std::pair<std::string, std::string>> fields;
    unique_fd file;
    std::uint64_t offset {0};
    std::uint64_t length {0};
    std::vector<char> body;
    bool gzip {false};

    auto add(std::string_view name, std::string_view value) -> void { fields.emplace_back(name, value); }
};

[[nodiscard]] constexpr auto lower(char value) noexcept -> char
{
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
}

[[nodiscard]] auto equal_lowercase(std::string_view text, std::string_view lowercase) noexcept -> bool
{
    return text.size() == lowercase.size() &&
        std::ranges::equal(text, lowercase, [](char left, char right) { return lower(left) == right; });
}

[[nodiscard]] auto trim(std::string_view text) noexcept -> std::string_view
{
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

// Every value of a repeated field, joined by commas.
[[nodiscard]] auto joined_field(const eventloop::http::request& request, std::string_view name)
    -> std::string
{
    std::string joined;
    for (const auto& field : request.headers()) {
        if (!equal_lowercase(field.name, name)) continue;
        if (!joined.empty()) joined += ", ";
        joined += field.value;
    }
    return joined;
}

[[nodiscard]] auto field_count(const eventloop::http::request& request, std::string_view name)
    -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(request.headers(),
        [&](const header& field) { return equal_lowercase(field.name, name); }));
}

// Whether an Accept-Encoding list accepts coding with a nonzero quality.
[[nodiscard]] auto accepts(std::string_view list, std::string_view coding) noexcept -> bool
{
    std::optional<bool> wildcard;
    while (!list.empty()) {
        const auto comma = list.find(',');
        auto item = trim(list.substr(0, comma));
        list = comma == std::string_view::npos ? std::string_view {} : list.substr(comma + 1);
        const auto semicolon = item.find(';');
        const auto name = trim(item.substr(0, semicolon));
        bool allowed = true;
        if (semicolon != std::string_view::npos) {
            auto parameter = trim(item.substr(semicolon + 1));
            if (parameter.size() >= 2 && lower(parameter[0]) == 'q' && parameter[1] == '=') {
                parameter = trim(parameter.substr(2));
                allowed = !parameter.empty() &&
                    parameter.find_first_not_of("0.") != std::string_view::npos;
            }
        }
        if (equal_lowercase(name, coding)) return allowed;
        if (name == "*") wildcard = allowed;
    }
    return wildcard.value_or(false);
}

[[nodiscard]] auto compressible(std::string_view mime) noexcept -> bool
{
    mime = mime.substr(0, mime.find(';'));
    return mime.starts_with("text/") || mime.ends_with("+json") || mime.ends_with("+xml") ||
        mime == "application/javascript" || mime == "application/json" ||
        mime == "application/xml" || mime == "application/wasm" || mime == "image/svg+xml";
}

[[nodiscard]] constexpr auto hex_value(char value) noexcept -> int
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

enum class path_error { invalid, too_long };

// Percent-decodes a request path, without its leading '/', rejecting ".."
// segments, NUL, backslash, and control characters.
[[nodiscard]] auto decode_path(std::string_view path) -> std::expected<std::string, path_error>
{
    if (path.empty() || path.front() != '/') return std::unexpected(path_error::invalid);
    std::string decoded;
    for (std::size_t input = 1; input < path.size(); ++input) {
        char value = path[input];
        if (value == '%') {
            if (input + 2 >= path.size()) return std::unexpected(path_error::invalid);
            const int high = hex_value(path[input + 1]);
            const int low = hex_value(path[input + 2]);
            if (high < 0 || low < 0) return std::unexpected(path_error::invalid);
            value = static_cast<char>((high << 4) | low);
            input += 2;
        }
        if (value == '\0' || value == '\\' || static_cast<unsigned char>(value) < 0x20)
            return std::unexpected(path_error::invalid);
        if (decoded.size() == max_decoded_path) return std::unexpected(path_error::too_long);
        decoded.push_back(value);
    }
    for (std::size_t start = 0; start <= decoded.size();) {
        const auto slash = decoded.find('/', start);
        const auto end = slash == std::string::npos ? decoded.size() : slash;
        if (std::string_view(decoded).substr(start, end - start) == "..")
            return std::unexpected(path_error::invalid);
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return decoded;
}

// A file or directory below a document root, with the directory holding it
// for sibling lookups.
struct opened_path {
    unique_fd file;
    unique_fd owned_parent;
    int parent {-1};
    std::string name;
    file_info info;
};

[[nodiscard]] auto open_child(int parent, const std::string& name, bool directory) noexcept -> unique_fd
{
    return unique_fd(::openat(parent, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                              (directory ? O_DIRECTORY : O_NONBLOCK)));
}

// Opens a decoded path below root one component at a time, refusing a
// symbolic link anywhere. O_NONBLOCK keeps a FIFO from blocking the loop.
[[nodiscard]] auto open_below(int root, std::string_view decoded) -> std::optional<opened_path>
{
    opened_path result;
    result.parent = root;
    // Each component is opened as a directory once a later one appears.
    bool pending = false;
    for (std::size_t start = 0; start < decoded.size();) {
        const auto slash = decoded.find('/', start);
        const auto end = slash == std::string_view::npos ? decoded.size() : slash;
        if (end > start) {
            if (pending) {
                auto next = open_child(result.parent, result.name, true);
                if (!next) return std::nullopt;
                result.owned_parent = std::move(next);
                result.parent = result.owned_parent.get();
            }
            result.name.assign(decoded.substr(start, end - start));
            pending = true;
        }
        start = end + 1;
    }
    result.file = pending ? open_child(result.parent, result.name, false)
                          : unique_fd(::openat(root, ".", O_RDONLY | O_CLOEXEC | O_DIRECTORY));
    if (!result.file || !stat_file(result.file.get(), result.info)) return std::nullopt;
    return result;
}

[[nodiscard]] auto read_whole(int descriptor, std::uint64_t size, std::uint64_t offset = 0)
    -> std::optional<std::vector<char>>
{
    std::vector<char> data(static_cast<std::size_t>(size));
    std::size_t done = 0;
    while (done < data.size()) {
        const auto count = ::pread(descriptor, data.data() + done, data.size() - done,
                                   static_cast<off_t>(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return std::nullopt;
        done += static_cast<std::size_t>(count);
    }
    return data;
}

auto append_url_encoded(std::string& output, std::string_view value) -> void
{
    constexpr char hex[] = "0123456789ABCDEF";
    for (const unsigned char byte : value) {
        if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
            byte == '~') {
            output.push_back(static_cast<char>(byte));
        } else {
            output.push_back('%');
            output.push_back(hex[byte >> 4]);
            output.push_back(hex[byte & 0x0f]);
        }
    }
}

auto append_html_escaped(std::string& output, std::string_view value) -> void
{
    for (const char byte : value) {
        switch (byte) {
        case '&': output += "&amp;"; break;
        case '<': output += "&lt;"; break;
        case '>': output += "&gt;"; break;
        case '"': output += "&quot;"; break;
        case '\'': output += "&#39;"; break;
        default: output.push_back(byte); break;
        }
    }
}

enum class listing_error { failed, too_large };

// Lists every entry except "." and ".." in byte-wise order, within
// listing_max_entries entries and listing_max_bytes of HTML.
[[nodiscard]] auto render_listing(unique_fd directory_file)
    -> std::expected<std::string, listing_error>
{
    struct closer {
        auto operator()(DIR* value) const noexcept -> void { (void)::closedir(value); }
    };
    const int descriptor = directory_file.get();
    std::unique_ptr<DIR, closer> directory(::fdopendir(descriptor));
    if (!directory) return std::unexpected(listing_error::failed);
    (void)directory_file.release();
    struct entry { std::string name; bool is_directory; };
    std::vector<entry> entries;
    for (;;) {
        errno = 0;
        const dirent* item = ::readdir(directory.get());
        if (item == nullptr) {
            if (errno != 0) return std::unexpected(listing_error::failed);
            break;
        }
        const std::string_view name {item->d_name};
        if (name == "." || name == "..") continue;
        bool is_directory = item->d_type == DT_DIR;
        if (item->d_type == DT_UNKNOWN) {
            struct stat status {};
            is_directory = ::fstatat(descriptor, item->d_name, &status, AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISDIR(status.st_mode);
        }
        if (entries.size() == listing_max_entries) return std::unexpected(listing_error::too_large);
        entries.push_back({std::string(name), is_directory});
    }
    std::ranges::sort(entries, {}, &entry::name);
    std::string output =
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>Index</title></head><body><h1>Index</h1><ul>\n";
    for (const auto& item : entries) {
        output += "<li><a href=\"";
        append_url_encoded(output, item.name);
        if (item.is_directory) output.push_back('/');
        output += "\">";
        append_html_escaped(output, item.name);
        if (item.is_directory) output.push_back('/');
        output += "</a></li>\n";
        if (output.size() > listing_max_bytes) return std::unexpected(listing_error::too_large);
    }
    output += "</ul></body></html>\n";
    if (output.size() > listing_max_bytes) return std::unexpected(listing_error::too_large);
    return output;
}

auto add_site_fields(reply& answer, const server_config& settings) -> void
{
    for (const auto& [name, value] : settings.headers) answer.add(name, value);
}

// An error status with the server's error page as its body, if one is
// configured and readable, and otherwise no body.
[[nodiscard]] auto error_reply(const site& selected, unsigned status, std::string_view body = {},
                               std::string_view type = {}) -> reply
{
    reply answer;
    answer.status = status;
    if (status == 405) answer.add("allow", allowed_methods);
    add_site_fields(answer, *selected.settings);
    const auto page = std::ranges::find(selected.settings->error_pages, status,
        &std::pair<unsigned, std::string>::first);
    if (page != selected.settings->error_pages.end()) {
        if (const auto decoded = decode_path(page->second)) {
            if (auto opened = open_below(selected.root.get(), *decoded);
                opened && opened->info.kind == file_info::type::regular &&
                opened->info.size <= max_error_page) {
                if (auto data = read_whole(opened->file.get(), opened->info.size)) {
                    answer.add("content-type", eventloop::http::mime_type_from_path(opened->name));
                    answer.body = std::move(*data);
                    return answer;
                }
            }
        }
    }
    if (!body.empty()) {
        answer.add("content-type", type);
        answer.body.assign(body.begin(), body.end());
    }
    return answer;
}

[[nodiscard]] auto cache_control(const server_config& settings, std::string_view path,
                                 std::string_view name) -> const std::string*
{
    const cache_rule* best = nullptr;
    for (const auto& rule : settings.cache_rules)
        if (rule.pattern.starts_with('/') && path.starts_with(rule.pattern) &&
            (!best || rule.pattern.size() > best->pattern.size()))
            best = &rule;
    if (best) return &best->value;
    for (const auto& rule : settings.cache_rules)
        if (rule.pattern.starts_with('*') && name.ends_with(std::string_view(rule.pattern).substr(1)) &&
            (!best || rule.pattern.size() > best->pattern.size()))
            best = &rule;
    return best ? &best->value : nullptr;
}

// Opens name.suffix beside a file when it is a regular file.
[[nodiscard]] auto open_variant(int parent, const std::string& name, std::string_view suffix,
                                file_info& info) -> unique_fd
{
    auto file = open_child(parent, name + std::string(suffix), false);
    if (!file || !stat_file(file.get(), info) || info.kind != file_info::type::regular) return {};
    return file;
}

[[nodiscard]] auto file_reply(const listener_context& context, const site& selected,
                              const eventloop::http::request& request, opened_path opened,
                              std::string_view path) -> reply
{
    const auto& settings = *selected.settings;
    const auto mime = eventloop::http::mime_type_from_path(opened.name);
    const bool negotiable = (settings.precompressed || settings.gzip) && compressible(mime);
    const auto accept_encoding = negotiable ? joined_field(request, "accept-encoding") : std::string {};
    std::string_view encoding;
    if (settings.precompressed && negotiable) {
        for (const auto& [coding, suffix] : {std::pair {std::string_view("br"), std::string_view(".br")},
                                            std::pair {std::string_view("gzip"), std::string_view(".gz")}}) {
            if (!accepts(accept_encoding, coding)) continue;
            file_info info;
            if (auto variant = open_variant(opened.parent, opened.name, suffix, info)) {
                opened.file = std::move(variant);
                opened.info = info;
                encoding = coding;
                break;
            }
        }
    }
    const bool gzip = encoding.empty() && settings.gzip && negotiable &&
        opened.info.size >= settings.gzip_min_size && opened.info.size <= settings.gzip_max_size &&
        accepts(accept_encoding, "gzip");
    if (gzip) encoding = "gzip";

    const auto none_match = joined_field(request, "if-none-match");
    const auto selection = select_file_response(opened.info, {
        none_match,
        request.header_value("if-modified-since").value_or(std::string_view {}),
        gzip || field_count(request, "range") != 1
            ? std::string_view {} : request.header_value("range").value_or(std::string_view {}),
        gzip ? std::string_view("-gzip") : std::string_view {}});

    reply answer;
    answer.status = selection.status;
    answer.add("last-modified", selection.modified);
    answer.add("etag", selection.etag);
    if (!gzip) answer.add("accept-ranges", "bytes");
    answer.add("content-type", mime);
    if (!encoding.empty()) answer.add("content-encoding", encoding);
    if (!selection.content_range.empty()) answer.add("content-range", selection.content_range);
    if (negotiable) answer.add("vary", "accept-encoding");
    if (const auto* value = cache_control(settings, path, opened.name)) answer.add("cache-control", *value);
    if (!context.alt_svc.empty()) answer.add("alt-svc", context.alt_svc);
    add_site_fields(answer, settings);
    if (selection.status == 304) {
        if (!gzip) answer.add("content-length", std::to_string(opened.info.size));
        return answer;
    }
    if (selection.status == 416) return answer;
    // A small body goes out with its header in one write instead of a file send.
    if (!gzip && selection.length <= inline_body_limit &&
        request.method() != method_type::head) {
        if (auto data = read_whole(opened.file.get(), selection.length, selection.offset)) {
            answer.body = std::move(*data);
            return answer;
        }
    }
    answer.file = std::move(opened.file);
    answer.offset = selection.offset;
    answer.length = selection.length;
    answer.gzip = gzip;
    return answer;
}

[[nodiscard]] auto prepare(const listener_context& context, const site& selected,
                           const eventloop::http::request& request) -> reply
{
    const auto method = request.method();
    if (method == method_type::options) {
        reply answer;
        answer.status = 204;
        answer.add("allow", allowed_methods);
        add_site_fields(answer, *selected.settings);
        return answer;
    }
    if (method != method_type::get && method != method_type::head) return error_reply(selected, 405);
    const auto decoded = decode_path(request.path());
    if (!decoded)
        return error_reply(selected, decoded.error() == path_error::too_long ? 414 : 400);
    auto opened = open_below(selected.root.get(), *decoded);
    if (!opened || opened->info.kind == file_info::type::other) return error_reply(selected, 404);
    const auto path = "/" + *decoded;
    if (opened->info.kind == file_info::type::regular)
        return file_reply(context, selected, request, std::move(*opened), path);

    const auto raw = request.path();
    if (raw.empty() || raw.back() != '/') {
        reply answer;
        answer.status = 308;
        std::string location {raw};
        location += '/';
        if (!request.query().empty()) location.append("?").append(request.query());
        answer.add("location", location);
        add_site_fields(answer, *selected.settings);
        return answer;
    }
    opened_path index;
    index.file = open_child(opened->file.get(), "index.html", false);
    if (index.file && stat_file(index.file.get(), index.info) &&
        index.info.kind == file_info::type::regular) {
        index.name = "index.html";
        index.owned_parent = std::move(opened->file);
        index.parent = index.owned_parent.get();
        return file_reply(context, selected, request, std::move(index), path);
    }
    if (!selected.settings->directory_listing) return error_reply(selected, 403);
    auto listing = render_listing(std::move(opened->file));
    if (!listing)
        return listing.error() == listing_error::too_large
            ? error_reply(selected, 500, "directory listing too large\n", "text/plain")
            : error_reply(selected, 500);
    reply answer;
    answer.add("content-type", "text/html; charset=utf-8");
    add_site_fields(answer, *selected.settings);
    answer.body.assign(listing->begin(), listing->end());
    return answer;
}

#ifdef STONEGATE_ZLIB
struct gzip_state {
    z_stream stream {};
    bool ready {false};
    std::array<unsigned char, 16384> input {};
    std::array<unsigned char, 16384> output {};
    ~gzip_state() { if (ready) (void)::deflateEnd(&stream); }
};

// Sends size bytes of file as one gzip member. Returns the compressed size.
auto send_gzip(eventloop::event_loop& loop, eventloop::http::response& response,
               std::span<const header> fields, int file, std::uint64_t size)
    -> eventloop::task<std::expected<std::uint64_t, std::error_code>>
{
    (void)loop;
    const auto failed = std::unexpected(std::make_error_code(std::errc::io_error));
    auto state = std::make_unique<gzip_state>();
    if (::deflateInit2(&state->stream, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        co_return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    state->ready = true;
    if (const auto started = eventloop::flatten_result(co_await response.async_start(200, fields));
        !started)
        co_return std::unexpected(started.error());
    std::uint64_t offset = 0, sent = 0;
    for (;;) {
        auto& stream = state->stream;
        if (stream.avail_in == 0 && offset < size) {
            const auto wanted = static_cast<std::size_t>(
                std::min<std::uint64_t>(state->input.size(), size - offset));
            const auto count = ::pread(file, state->input.data(), wanted, static_cast<off_t>(offset));
            if (count <= 0) co_return failed; // The file shrank or failed; abandon the response.
            offset += static_cast<std::uint64_t>(count);
            stream.next_in = state->input.data();
            stream.avail_in = static_cast<uInt>(count);
        }
        stream.next_out = state->output.data();
        stream.avail_out = static_cast<uInt>(state->output.size());
        const int result = ::deflate(&stream, offset == size && stream.avail_in == 0 ? Z_FINISH
                                                                                  : Z_NO_FLUSH);
        if (result != Z_OK && result != Z_STREAM_END && result != Z_BUF_ERROR) co_return failed;
        const auto produced = state->output.size() - stream.avail_out;
        if (produced != 0) {
            const auto written = eventloop::flatten_result(co_await response.async_write(
                std::as_bytes(std::span(state->output).first(produced))));
            if (!written) co_return std::unexpected(written.error());
            sent += produced;
        }
        if (result == Z_STREAM_END) break;
    }
    if (const auto finished = eventloop::flatten_result(co_await response.async_finish());
        !finished)
        co_return std::unexpected(finished.error());
    co_return sent;
}
#endif

// Sends the reply; returns the body bytes sent.
auto send(eventloop::event_loop& loop, eventloop::http::response& response, reply& answer,
          bool head) -> eventloop::task<std::expected<std::uint64_t, std::error_code>>
{
    using eventloop::flatten_result;
    std::vector<header> fields;
    fields.reserve(answer.fields.size());
    for (const auto& [name, value] : answer.fields) fields.push_back({name, value});
#ifdef STONEGATE_ZLIB
    if (answer.gzip && !head)
        co_return flatten_result(co_await send_gzip(loop, response, fields, answer.file.get(),
                                                    answer.length));
#else
    (void)loop;
#endif
    if (answer.gzip || answer.status == 304) {
        if (auto started = flatten_result(co_await response.async_start(answer.status, fields));
            !started)
            co_return std::unexpected(started.error());
        if (auto finished = flatten_result(co_await response.async_finish()); !finished)
            co_return std::unexpected(finished.error());
        co_return 0;
    }
    if (answer.file) {
        const auto sent = flatten_result(co_await response.async_send_file(answer.status, fields,
            std::move(answer.file), answer.offset, answer.length));
        if (!sent) co_return std::unexpected(sent.error());
        co_return head ? 0 : answer.length;
    }
    const auto sent = flatten_result(co_await response.async_send(answer.status, fields,
                                                                  std::as_bytes(std::span(answer.body))));
    if (!sent) co_return std::unexpected(sent.error());
    co_return head ? 0 : answer.body.size();
}

// Appends text with quotes, backslashes, and non-printing bytes as \xHH.
auto append_escaped(std::string& line, std::string_view text) -> void
{
    constexpr char hex[] = "0123456789abcdef";
    if (text.empty()) {
        line.push_back('-');
        return;
    }
    for (const unsigned char byte : text) {
        if (byte < 0x20 || byte >= 0x7f || byte == '"' || byte == '\\') {
            line += "\\x";
            line.push_back(hex[byte >> 4]);
            line.push_back(hex[byte & 0x0f]);
        } else {
            line.push_back(static_cast<char>(byte));
        }
    }
}

// The local time field of the Common Log Format, in UTC, formatted at most
// once per second per thread.
[[nodiscard]] auto log_time() -> std::string_view
{
    thread_local std::array<char, 32> text {};
    thread_local std::time_t second = -1;
    thread_local std::size_t size = 0;
    const auto now = std::time(nullptr);
    if (now != second) {
        std::tm parts {};
        size = ::gmtime_r(&now, &parts) ? std::strftime(text.data(), text.size(),
                                                         "%d/%b/%Y:%H:%M:%S +0000", &parts) : 0;
        second = now;
    }
    return {text.data(), size};
}

// One Combined Log Format line, followed by the host and seconds taken:
// client - - [time] "METHOD target PROTOCOL" status bytes "referer"
// "user-agent" "host" seconds. The client is "-" unless real_ip_header names
// a field, whose first entry is used.
auto log_request(const site& selected, const eventloop::http::request& request, unsigned status,
                 std::optional<std::uint64_t> bytes, std::chrono::steady_clock::time_point start)
    -> void
{
    if (selected.log == nullptr) return;
    try {
        std::string line;
        line.reserve(256);
        std::string_view client;
        if (!selected.settings->real_ip_header.empty())
            if (const auto value = request.header_value(selected.settings->real_ip_header))
                client = trim(value->substr(0, value->find(',')));
        append_escaped(line, client);
        line += " - - [";
        line += log_time();
        line += "] \"";
        append_escaped(line, request.method_name());
        line.push_back(' ');
        append_escaped(line, request.path());
        if (!request.query().empty()) {
            line.push_back('?');
            append_escaped(line, request.query());
        }
        using eventloop::http::protocol;
        line += request.protocol() == protocol::http3 ? " HTTP/3\" " :
            request.protocol() == protocol::http2 ? " HTTP/2\" " : " HTTP/1.1\" ";
        line += std::to_string(status);
        line.push_back(' ');
        line += bytes ? std::to_string(*bytes) : std::string("-");
        line += " \"";
        append_escaped(line, request.header_value("referer").value_or(std::string_view {}));
        line += "\" \"";
        append_escaped(line, request.header_value("user-agent").value_or(std::string_view {}));
        line += "\" \"";
        append_escaped(line, request.authority());
        const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start);
        std::array<char, 32> seconds {};
        const int size = std::snprintf(seconds.data(), seconds.size(), "\" %.3f\n", elapsed.count());
        if (size > 0) line.append(seconds.data(), static_cast<std::size_t>(size));
        selected.log->append(line);
    } catch (...) {
        // A line that cannot be built is skipped; the response is unaffected.
    }
}

auto respond(eventloop::event_loop& loop, eventloop::http::request& request,
             eventloop::http::response& response, bool health) -> eventloop::task<void>
{
    const request_scope scope;
    const auto& context = *static_cast<const listener_context*>(request.route_context());
    const auto& selected = context.sites->select(request.authority());
    reply answer;
    try {
        if (!context.redirect_origin.empty()) {
            answer.status = 308;
            std::string location = context.redirect_origin;
            location += request.path();
            if (!request.query().empty()) location.append("?").append(request.query());
            answer.add("location", location);
        } else if (health) {
            answer.add("content-type", "text/plain; charset=utf-8");
            answer.add("cache-control", "no-store");
            constexpr std::string_view body = "ok\n";
            answer.body.assign(body.begin(), body.end());
        } else {
            answer = prepare(context, selected, request);
        }
    } catch (const std::exception&) {
        answer = reply {};
        answer.status = 500;
    }
    const auto sent = eventloop::flatten_result(co_await send(loop, response, answer,
        request.method() == method_type::head));
    log_request(selected, request, answer.status,
                sent ? std::optional {*sent} : std::nullopt, scope.start);
}

auto serve(eventloop::event_loop& loop, eventloop::http::request& request,
           eventloop::http::response& response) -> eventloop::task<void>
{
    co_await respond(loop, request, response, false);
}

auto healthz(eventloop::event_loop& loop, eventloop::http::request& request,
             eventloop::http::response& response) -> eventloop::task<void>
{
    co_await respond(loop, request, response, true);
}

} // namespace

auto site_group::select(std::string_view authority) const noexcept -> const site&
{
    // Drop the port and a trailing dot; compare without case.
    auto host = authority;
    if (host.starts_with('[')) host = host.substr(0, host.find(']') + 1);
    else if (const auto colon = host.rfind(':'); colon != std::string_view::npos &&
             host.find(':') == colon)
        host = host.substr(0, colon);
    if (host.ends_with('.')) host.remove_suffix(1);
    const site* wildcard = nullptr;
    std::size_t wildcard_size = 0;
    for (const auto& candidate : sites) {
        for (const auto& name : candidate.settings->server_names) {
            if (!name.starts_with("*.")) {
                if (equal_lowercase(host, name)) return candidate;
                continue;
            }
            const auto suffix = std::string_view(name).substr(1);
            if (host.size() > suffix.size() && name.size() > wildcard_size &&
                equal_lowercase(host.substr(host.size() - suffix.size()), suffix)) {
                wildcard = &candidate;
                wildcard_size = name.size();
            }
        }
    }
    return wildcard ? *wildcard : sites[fallback];
}

auto make_router(const listener_context& context) -> std::shared_ptr<const eventloop::http::router>
{
    auto routes = std::make_shared<eventloop::http::router>();
    auto* data = const_cast<listener_context*>(&context);
    const auto add = [&](auto result, std::string_view what) {
        if (!result) throw std::runtime_error("register " + std::string(what));
    };
    add(routes->add(method_type::get, "/healthz", healthz, data), "/healthz");
    for (const auto method : {method_type::get, method_type::options, method_type::post,
                              method_type::put, method_type::delete_, method_type::patch,
                              method_type::trace})
        add(routes->add_prefix(method, "/", serve, data), "static route");
    return routes;
}

auto active_requests() noexcept -> std::size_t
{
    return active;
}

} // namespace stonegate
