#include "proxy.h"

#include "text.h"

#include "eventloop/task_composition.h"
#include "eventloop/tcp_stream.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace stonegate {
namespace {

using eventloop::flatten_result;
using eventloop::http::header;
using eventloop::http::method_type;
using io_result = std::expected<std::size_t, std::error_code>;
using void_result = std::expected<void, std::error_code>;
// A local response status when forwarding fails before the response starts.
using step_result = std::expected<void, unsigned>;
template<typename T> using step = std::expected<T, unsigned>;

// The upstream response head must fit; body bytes are read through it too.
constexpr std::size_t input_size = 32 * 1024;
constexpr std::size_t body_chunk = 16 * 1024;
// Room before a forwarded request body chunk for its "HEX\r\n" size line.
constexpr std::size_t chunk_prefix = 18;
constexpr std::size_t max_chunk_line = 4096;

// Request fields the proxy sets itself or that apply to one connection only.
constexpr std::string_view dropped_request_fields[] {
    "connection", "content-length", "expect", "host", "http2-settings", "keep-alive",
    "proxy-connection", "sec-websocket-extensions", "sec-websocket-key",
    "sec-websocket-version", "te", "trailer", "transfer-encoding", "upgrade", "x-forwarded-for",
    "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
};
constexpr std::string_view dropped_response_fields[] {
    "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding",
    "upgrade",
};

[[nodiscard]] auto failure(std::errc code) -> std::unexpected<std::error_code>
{
    return std::unexpected(std::make_error_code(code));
}

// A step whose task failed to run answers 500.
template<typename T>
[[nodiscard]] auto settle(std::expected<step<T>, eventloop::task_result> value) -> step<T>
{
    if (!value) return std::unexpected(500u);
    return std::move(*value);
}

[[nodiscard]] auto timed_out(const std::error_code& error) noexcept -> bool
{
    return error == std::errc::timed_out;
}

[[nodiscard]] auto is_token(std::string_view text) noexcept -> bool
{
    return !text.empty() && std::ranges::all_of(text, [](unsigned char byte) {
        return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') ||
            std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(byte)) !=
                std::string_view::npos;
    });
}

// Visible ASCII, spaces, and tabs: a value that cannot split a field.
[[nodiscard]] auto is_field_value(std::string_view text) noexcept -> bool
{
    return std::ranges::all_of(text, [](unsigned char byte) {
        return byte == '\t' || (byte >= 0x20 && byte != 0x7f);
    });
}

// Whether a comma-separated field value lists name, without case.
[[nodiscard]] auto lists(std::string_view list, std::string_view name) noexcept -> bool
{
    while (!list.empty()) {
        const auto comma = list.find(',');
        if (equal_lowercase(trim(list.substr(0, comma)), name)) return true;
        list = comma == std::string_view::npos ? std::string_view {} : list.substr(comma + 1);
    }
    return false;
}

[[nodiscard]] auto lowercase(std::string_view text) -> std::string
{
    std::string result(text);
    std::ranges::transform(result, result.begin(), lower);
    return result;
}

[[nodiscard]] auto format_address(const eventloop::ip_endpoint& endpoint) -> std::string
{
    std::array<char, INET6_ADDRSTRLEN> text {};
    const int family = endpoint.address_family == eventloop::ip_endpoint::family::ipv4
        ? AF_INET : AF_INET6;
    if (::inet_ntop(family, endpoint.address.data(), text.data(), text.size()) == nullptr)
        return {};
    return text.data();
}

[[nodiscard]] auto base64(std::span<const unsigned char> data) -> std::string
{
    std::string text(4 * ((data.size() + 2) / 3), '\0');
    const int size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(text.data()), data.data(),
                                     static_cast<int>(data.size()));
    text.resize(size < 0 ? 0 : static_cast<std::size_t>(size));
    return text;
}

// A fresh Sec-WebSocket-Key: sixteen random bytes in base64. Empty on failure.
[[nodiscard]] auto websocket_key() -> std::string
{
    std::array<unsigned char, 16> nonce {};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) return {};
    return base64(nonce);
}

// RFC 6455 section 4.2.2: the Sec-WebSocket-Accept value for a key.
[[nodiscard]] auto websocket_accept(std::string_view key) -> std::string
{
    const auto input = std::string(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int size = 0;
    if (EVP_Digest(input.data(), input.size(), digest.data(), &size, EVP_sha1(), nullptr) != 1)
        return {};
    return base64(std::span(digest).first(size));
}

// An HTTP/1.1 Upgrade to WebSocket, or HTTP/2 and HTTP/3 Extended CONNECT.
[[nodiscard]] auto is_websocket(const eventloop::http::request& request) noexcept -> bool
{
    if (request.protocol() != eventloop::http::protocol::http1_1)
        return request.method() == method_type::connect &&
            request.connect_protocol() == "websocket";
    bool upgrade = false, connection = false;
    for (const auto& field : request.headers()) {
        if (equal_lowercase(field.name, "upgrade")) upgrade |= lists(field.value, "websocket");
        if (equal_lowercase(field.name, "connection")) connection |= lists(field.value, "upgrade");
    }
    return request.method() == method_type::get && upgrade && connection;
}

// The upstream stream, closed when the exchange ends. The hold keeps it valid
// when the upstream resets while the proxy waits on the client.
class upstream_connection {
public:
    upstream_connection() = default;
    upstream_connection(const upstream_connection&) = delete;
    auto operator=(const upstream_connection&) -> upstream_connection& = delete;
    ~upstream_connection()
    {
        if (auto* stream = hold_.get()) stream->close();
    }

    auto open(eventloop::event_loop& loop, const eventloop::ip_endpoint& endpoint)
        -> eventloop::tcp_stream&
    {
        auto owned = std::make_unique<eventloop::tcp_stream>(loop, endpoint);
        auto& stream = *owned;
        loop.add(std::move(owned));
        hold_ = eventloop::tcp_stream_hold(stream);
        return stream;
    }

private:
    eventloop::tcp_stream_hold hold_;
};

enum class framing { none, length, chunked, until_close };

// One forwarded request. It lives on the heap so the coroutine frames stay
// in the small pooled size classes.
struct exchange {
    exchange(eventloop::http::request& request, eventloop::http::response& response,
             const site& target)
        : request(request), response(response), target(target),
          timeout(target.settings->proxy_timeout_ms) {}

    eventloop::http::request& request;
    eventloop::http::response& response;
    const site& target;
    std::chrono::milliseconds timeout;
    upstream_connection upstream;
    eventloop::tcp_stream* stream {nullptr};

    // Request side: the head, then body chunks behind room for a size line.
    std::string head;
    std::array<std::byte, chunk_prefix + body_chunk + 2> output;

    // Response side: unconsumed upstream bytes are input[start, end).
    std::array<std::byte, input_size> input;
    std::size_t start {0};
    std::size_t end {0};
    unsigned status {0};
    framing body {framing::none};
    std::uint64_t remaining {0};
    std::vector<std::pair<std::string, std::string>> fields;
    std::vector<header> views;
    std::uint64_t sent {0};
    // The key sent upstream for a WebSocket request, else empty.
    std::string websocket_key;
    // A 101 response that completes the WebSocket handshake.
    bool upgraded {false};

    [[nodiscard]] auto buffered() const noexcept -> std::string_view
    {
        return {reinterpret_cast<const char*>(input.data()) + start, end - start};
    }
};

// Awaits an operation for at most limit; expiry is timed_out.
template<typename T>
auto bounded(eventloop::event_loop& loop,
             eventloop::task<std::expected<T, std::error_code>> operation,
             std::chrono::milliseconds limit) -> eventloop::task<std::expected<T, std::error_code>>
{
    using result = eventloop::timeout_result<std::expected<T, std::error_code>>;
    auto outcome = co_await eventloop::with_timeout(loop, std::move(operation), limit);
    if (!outcome) co_return failure(std::errc::operation_canceled);
    if (outcome->state == result::outcome::timed_out) co_return failure(std::errc::timed_out);
    if (!outcome->result) co_return failure(std::errc::operation_canceled);
    co_return flatten_result(std::move(*outcome->result));
}

auto connect(eventloop::event_loop& loop, eventloop::tcp_stream& stream)
    -> eventloop::task<void_result>
{
    (void)loop;
    co_return co_await stream.async_connect();
}

auto read_some(eventloop::event_loop& loop, eventloop::tcp_stream& stream,
               std::span<std::byte> buffer) -> eventloop::task<io_result>
{
    (void)loop;
    co_return co_await stream.async_read_some(buffer);
}

auto write_all(eventloop::event_loop& loop, eventloop::tcp_stream& stream,
               std::span<const std::byte> data) -> eventloop::task<void_result>
{
    (void)loop;
    while (!data.empty()) {
        const auto written = co_await stream.async_write_some(data);
        if (!written) co_return std::unexpected(written.error());
        if (*written == 0) co_return failure(std::errc::broken_pipe);
        data = data.subspan(*written);
    }
    co_return void_result {};
}

auto send_upstream(eventloop::event_loop& loop, exchange& state, std::span<const std::byte> data)
    -> eventloop::task<step_result>
{
    const auto written = flatten_result(co_await bounded(loop, write_all(loop, *state.stream, data),
                                                         state.timeout));
    if (!written) co_return std::unexpected(timed_out(written.error()) ? 504u : 502u);
    co_return step_result {};
}

// Reads the next request body chunk into output after the size-line room.
auto read_client(eventloop::event_loop& loop, exchange& state, std::size_t limit)
    -> eventloop::task<step<std::size_t>>
{
    const auto buffer = std::span(state.output).subspan(chunk_prefix, std::min(limit, body_chunk));
    const auto read = flatten_result(co_await bounded(loop, state.request.async_read_body(buffer),
                                                      state.timeout));
    if (!read) co_return std::unexpected(timed_out(read.error()) ? 408u : 400u);
    co_return *read;
}

// Whether the method and target can go into an HTTP/1.1 request line.
[[nodiscard]] auto valid_request_line(const eventloop::http::request& request) noexcept -> bool
{
    const auto visible = [](std::string_view text) {
        return std::ranges::all_of(text,
            [](unsigned char byte) { return byte > 0x20 && byte != 0x7f; });
    };
    return is_token(request.method_name()) && request.path().starts_with('/') &&
        visible(request.path()) && visible(request.query());
}

// The request head for the upstream, with the body framing chosen.
auto build_head(exchange& state, bool secure, std::optional<std::uint64_t> length, bool chunked)
    -> void
{
    const auto& request = state.request;
    const auto& settings = *state.target.settings;
    std::string connection;
    for (const auto& field : request.headers())
        if (equal_lowercase(field.name, "connection")) connection.append(field.value).append(",");
    const bool trusted = !settings.real_ip_header.empty();
    std::string forwarded_for;
    auto& head = state.head;
    head.reserve(1024);
    // HTTP/2 and HTTP/3 WebSockets arrive as CONNECT; HTTP/1.1 opens them with GET.
    const bool websocket = !state.websocket_key.empty();
    head.append(websocket ? "GET" : request.method_name()).append(" ").append(request.path());
    if (!request.query().empty()) head.append("?").append(request.query());
    head.append(" HTTP/1.1\r\nhost: ");
    const auto authority = request.authority();
    if (!authority.empty() && is_field_value(authority)) head.append(authority);
    else head.append(settings.upstream_address.contains(':') ? "[" + settings.upstream_address + "]"
                                                            : settings.upstream_address);
    head.append("\r\n");
    std::string cookies;
    for (const auto& field : request.headers()) {
        const auto name = lowercase(field.name);
        if (name.empty() || name.front() == ':' || !is_token(name) ||
            !is_field_value(field.value) || std::ranges::contains(dropped_request_fields, name) ||
            (!trusted && name == "forwarded") || lists(connection, name)) {
            if (trusted && name == "x-forwarded-for" && is_field_value(field.value)) {
                if (!forwarded_for.empty()) forwarded_for += ", ";
                forwarded_for += trim(field.value);
            }
            continue;
        }
        // HTTP/2 and HTTP/3 may split cookies; HTTP/1.1 takes one field.
        if (name == "cookie") {
            if (!cookies.empty()) cookies += "; ";
            cookies += field.value;
            continue;
        }
        head.append(name).append(": ").append(field.value).append("\r\n");
    }
    if (!cookies.empty()) head.append("cookie: ").append(cookies).append("\r\n");
    head.append("x-forwarded-proto: ").append(secure ? "https" : "http").append("\r\n");
    if (const auto peer = request.peer()) {
        if (!forwarded_for.empty()) forwarded_for += ", ";
        forwarded_for += format_address(*peer);
    }
    if (!forwarded_for.empty())
        head.append("x-forwarded-for: ").append(forwarded_for).append("\r\n");
    if (const auto client = client_address(request, settings.real_ip_header);
        !client.empty() && is_field_value(client))
        head.append("x-real-ip: ").append(client).append("\r\n");
    if (!authority.empty() && is_field_value(authority))
        head.append("x-forwarded-host: ").append(authority).append("\r\n");
    if (websocket) {
        head.append("sec-websocket-version: 13\r\nsec-websocket-key: ").append(state.websocket_key)
            .append("\r\nupgrade: websocket\r\nconnection: upgrade\r\n\r\n");
        return;
    }
    if (length) head.append("content-length: ").append(std::to_string(*length)).append("\r\n");
    else if (chunked) head.append("transfer-encoding: chunked\r\n");
    else if (request.method() == method_type::post || request.method() == method_type::put ||
             request.method() == method_type::patch)
        head.append("content-length: 0\r\n");
    head.append("connection: close\r\n\r\n");
}

// Sends the head and the request body. first is a chunk already read into
// output when the body has no declared length.
auto send_request(eventloop::event_loop& loop, exchange& state, std::optional<std::uint64_t> length,
                  std::size_t first) -> eventloop::task<step_result>
{
    if (auto sent = settle(co_await send_upstream(loop, state,
                                                  std::as_bytes(std::span(state.head)))); !sent)
        co_return sent;
    const auto limit = state.target.settings->proxy_max_request_body;
    if (length) {
        for (auto remaining = *length; remaining != 0;) {
            const auto read = settle(co_await read_client(loop, state, static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining, body_chunk))));
            if (!read) co_return std::unexpected(read.error());
            if (*read == 0) co_return std::unexpected(400u);
            remaining -= *read;
            if (auto sent = settle(co_await send_upstream(loop, state,
                    std::span(state.output).subspan(chunk_prefix, *read))); !sent)
                co_return sent;
        }
        co_return step_result {};
    }
    if (first == 0) co_return step_result {};
    std::uint64_t total = 0;
    for (auto size = first; size != 0;) {
        total += size;
        if (total > limit) co_return std::unexpected(413u);
        // "HEX\r\n" ends where the chunk starts; "\r\n" follows it.
        std::array<char, 16> digits {};
        const auto converted =
            std::to_chars(digits.data(), digits.data() + digits.size(), size, 16);
        const auto count = static_cast<std::size_t>(converted.ptr - digits.data());
        const auto line = chunk_prefix - count - 2;
        std::ranges::transform(std::span(digits).first(count), state.output.begin() +
            static_cast<std::ptrdiff_t>(line), [](char digit) { return std::byte(digit); });
        state.output[chunk_prefix - 2] = std::byte {'\r'};
        state.output[chunk_prefix - 1] = std::byte {'\n'};
        state.output[chunk_prefix + size] = std::byte {'\r'};
        state.output[chunk_prefix + size + 1] = std::byte {'\n'};
        if (auto sent = settle(co_await send_upstream(loop, state,
                std::span(state.output).subspan(line, count + 2 + size + 2))); !sent)
            co_return sent;
        const auto read = settle(co_await read_client(loop, state, body_chunk));
        if (!read) co_return std::unexpected(read.error());
        size = *read;
    }
    constexpr std::string_view last = "0\r\n\r\n";
    co_return settle(co_await send_upstream(loop, state, std::as_bytes(std::span(last))));
}

// Reads more upstream bytes into input, compacting it first. Zero is EOF.
auto fill(eventloop::event_loop& loop, exchange& state) -> eventloop::task<io_result>
{
    if (state.start == state.end) state.start = state.end = 0;
    else if (state.end == state.input.size()) {
        const auto first = state.input.begin();
        std::copy(first + static_cast<std::ptrdiff_t>(state.start),
                  first + static_cast<std::ptrdiff_t>(state.end), first);
        state.end -= state.start;
        state.start = 0;
    }
    if (state.end == state.input.size()) co_return failure(std::errc::message_size);
    const auto read = flatten_result(co_await bounded(loop, read_some(loop, *state.stream,
        std::span(state.input).subspan(state.end)), state.timeout));
    if (!read) co_return std::unexpected(read.error());
    state.end += *read;
    co_return *read;
}

// Parses one response head, without its blank line. Returns false when it is
// malformed. A 1xx head other than 101 sets status and nothing else.
[[nodiscard]] auto parse_head(exchange& state, std::string_view head) -> bool
{
    const auto line_end = head.find('\n');
    auto line = head.substr(0, line_end);
    if (line.ends_with('\r')) line.remove_suffix(1);
    if (!line.starts_with("HTTP/1.") || line.size() < 12 || line[8] != ' ' ||
        (line.size() > 12 && line[12] != ' '))
        return false;
    unsigned status = 0;
    const auto digits = line.substr(9, 3);
    const auto [end, error] = std::from_chars(digits.data(), digits.data() + 3, status);
    if (error != std::errc {} || end != digits.data() + 3 || status < 100) return false;
    state.status = status;
    if (status < 200 && status != 101) return true;
    state.fields.clear();
    std::optional<std::uint64_t> length;
    bool chunked = false, encoded = false;
    std::string_view connection;
    bool upgrade = false, accepted = false;
    auto rest = line_end == std::string_view::npos ? std::string_view {}
                                                   : head.substr(line_end + 1);
    while (!rest.empty()) {
        const auto next = rest.find('\n');
        line = rest.substr(0, next);
        rest = next == std::string_view::npos ? std::string_view {} : rest.substr(next + 1);
        if (line.ends_with('\r')) line.remove_suffix(1);
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || !is_token(line.substr(0, colon))) return false;
        const auto value = trim(line.substr(colon + 1));
        if (!is_field_value(value)) return false;
        auto name = lowercase(line.substr(0, colon));
        if (name == "content-length") {
            std::uint64_t parsed = 0;
            const auto [last, failed] = std::from_chars(value.data(), value.data() + value.size(),
                                                        parsed);
            if (value.empty() || failed != std::errc {} || last != value.data() + value.size() ||
                (length && *length != parsed))
                return false;
            length = parsed;
        } else if (name == "transfer-encoding") {
            encoded = true;
            const auto coding = trim(value.substr(value.rfind(',') + 1));
            chunked = equal_lowercase(coding, "chunked");
        } else if (name == "connection") {
            connection = value;
        } else if (name == "upgrade") {
            upgrade = lists(value, "websocket");
        } else if (name == "sec-websocket-accept") {
            accepted = !state.websocket_key.empty() && value == websocket_accept(state.websocket_key);
        }
        state.fields.emplace_back(std::move(name), value);
    }
    state.upgraded = status == 101 && upgrade && accepted;
    const bool bodyless = state.request.method() == method_type::head || status == 101 ||
        status == 204 || status == 304;
    if (bodyless) state.body = framing::none;
    else if (encoded) state.body = chunked ? framing::chunked : framing::until_close;
    else if (length) state.body = framing::length;
    else state.body = framing::until_close;
    state.remaining = length.value_or(0);
    // Keep fields valid for every protocol; the site's headers replace
    // upstream fields of the same name.
    const auto& settings = *state.target.settings;
    std::erase_if(state.fields, [&](const auto& field) {
        const auto& [name, value] = field;
        return std::ranges::contains(dropped_response_fields, name) || lists(connection, name) ||
            (name == "content-length" && (encoded || status == 204)) ||
            std::ranges::contains(settings.headers, name,
                                  &std::pair<std::string, std::string>::first);
    });
    state.fields.insert(state.fields.end(), settings.headers.begin(), settings.headers.end());
    return true;
}

// Reads response heads until a final one, skipping 1xx responses.
auto receive_head(eventloop::event_loop& loop, exchange& state) -> eventloop::task<step_result>
{
    for (;;) {
        const auto buffered = state.buffered();
        auto boundary = buffered.find("\r\n\r\n");
        std::size_t separator = 4;
        if (const auto bare = buffered.find("\n\n"); bare < boundary) {
            boundary = bare;
            separator = 2;
        }
        if (boundary == std::string_view::npos) {
            if (state.start == 0 && state.end == state.input.size())
                co_return std::unexpected(502u);
            const auto read = flatten_result(co_await fill(loop, state));
            if (!read) co_return std::unexpected(timed_out(read.error()) ? 504u : 502u);
            if (*read == 0) co_return std::unexpected(502u);
            continue;
        }
        if (!parse_head(state, buffered.substr(0, boundary))) co_return std::unexpected(502u);
        state.start += boundary + separator;
        // 101 completes only the WebSocket handshake this proxy asked for.
        if (state.status == 101) {
            if (!state.upgraded) co_return std::unexpected(502u);
            co_return step_result {};
        }
        if (state.status > 599) co_return std::unexpected(502u);
        if (state.status >= 200) co_return step_result {};
    }
}

auto write_client(eventloop::event_loop& loop, exchange& state, std::size_t size)
    -> eventloop::task<void_result>
{
    (void)loop;
    const auto data = std::span(state.input).subspan(state.start, size);
    state.start += size;
    state.sent += size;
    co_return flatten_result(co_await state.response.async_write(data));
}

// Finds the next line in the buffered input, reading more as needed, and
// consumes it. Returns it without its line ending.
auto next_line(eventloop::event_loop& loop, exchange& state)
    -> eventloop::task<std::expected<std::string, std::error_code>>
{
    for (;;) {
        const auto buffered = state.buffered();
        if (const auto newline = buffered.find('\n'); newline != std::string_view::npos) {
            auto line = buffered.substr(0, newline);
            if (line.ends_with('\r')) line.remove_suffix(1);
            std::string result(line);
            state.start += newline + 1;
            co_return result;
        }
        if (buffered.size() > max_chunk_line) co_return failure(std::errc::bad_message);
        const auto read = flatten_result(co_await fill(loop, state));
        if (!read) co_return std::unexpected(read.error());
        if (*read == 0) co_return failure(std::errc::bad_message);
    }
}

// Streams the response body from the upstream to the client.
auto relay_body(eventloop::event_loop& loop, exchange& state) -> eventloop::task<void_result>
{
    if (state.body == framing::none) co_return void_result {};
    if (state.body != framing::chunked) {
        const bool counted = state.body == framing::length;
        for (;;) {
            auto available = state.end - state.start;
            if (counted) available = static_cast<std::size_t>(
                std::min<std::uint64_t>(available, state.remaining));
            if (available != 0) {
                if (auto written = flatten_result(co_await write_client(loop, state, available));
                    !written)
                    co_return written;
                if (counted) state.remaining -= available;
            }
            if (counted && state.remaining == 0) co_return void_result {};
            const auto read = flatten_result(co_await fill(loop, state));
            if (!read) co_return std::unexpected(read.error());
            if (*read == 0) {
                if (counted) co_return failure(std::errc::bad_message);
                co_return void_result {};
            }
        }
    }
    for (;;) {
        const auto line = flatten_result(co_await next_line(loop, state));
        if (!line) co_return std::unexpected(line.error());
        const auto digits = trim(std::string_view(*line).substr(0, line->find(';')));
        std::uint64_t size = 0;
        const auto [last, failed] = std::from_chars(digits.data(), digits.data() + digits.size(),
                                                    size, 16);
        if (digits.empty() || digits.size() > 15 || failed != std::errc {} ||
            last != digits.data() + digits.size())
            co_return failure(std::errc::bad_message);
        if (size == 0) break;
        while (size != 0) {
            if (state.start == state.end) {
                const auto read = flatten_result(co_await fill(loop, state));
                if (!read) co_return std::unexpected(read.error());
                if (*read == 0) co_return failure(std::errc::bad_message);
            }
            const auto available = static_cast<std::size_t>(
                std::min<std::uint64_t>(state.end - state.start, size));
            if (auto written = flatten_result(co_await write_client(loop, state, available));
                !written)
                co_return written;
            size -= available;
        }
        const auto ending = flatten_result(co_await next_line(loop, state));
        if (!ending) co_return std::unexpected(ending.error());
        if (!ending->empty()) co_return failure(std::errc::bad_message);
    }
    // Trailers are dropped.
    for (;;) {
        const auto line = flatten_result(co_await next_line(loop, state));
        if (!line) co_return std::unexpected(line.error());
        if (line->empty()) co_return void_result {};
    }
}

// Relays client WebSocket bytes upstream until either side stops.
auto client_to_upstream(eventloop::event_loop& loop, exchange& state,
                        eventloop::http::websocket_stream& socket) -> eventloop::task<void>
{
    for (;;) {
        const auto read = flatten_result(co_await socket.async_read_some(state.output));
        if (!read || *read == 0) co_return;
        const auto sent = flatten_result(co_await bounded(loop, write_all(loop, *state.stream,
            std::span(state.output).first(*read)), state.timeout));
        if (!sent) co_return;
    }
}

// Relays upstream bytes, starting with any after the 101 head, to the client.
auto upstream_to_client(eventloop::event_loop& loop, exchange& state,
                        eventloop::http::websocket_stream& socket) -> eventloop::task<void>
{
    (void)loop;
    for (;;) {
        if (state.start != state.end) {
            const auto written = flatten_result(co_await socket.async_write_some(
                std::span(state.input).subspan(state.start, state.end - state.start)));
            if (!written || *written == 0) co_return;
            state.start += *written;
            state.sent += *written;
            continue;
        }
        state.start = state.end = 0;
        const auto read = co_await state.stream->async_read_some(state.input);
        if (!read || *read == 0) co_return;
        state.end = *read;
    }
}

// Accepts the client's WebSocket with the upstream's subprotocol, then relays
// bytes both ways without a timeout until either side closes; the other
// direction is then cancelled. WebSocket frames pass unchanged.
auto tunnel(eventloop::event_loop& loop, exchange& state) -> eventloop::task<step<proxy_outcome>>
{
    std::string_view selected;
    for (const auto& [name, value] : state.fields)
        if (name == "sec-websocket-protocol") selected = value;
    auto accepted = co_await state.request.async_accept_websocket(selected);
    if (!accepted) co_return std::unexpected(500u);
    if (!*accepted) co_return std::unexpected(400u);
    auto& socket = **accepted;
    (void)co_await eventloop::race(client_to_upstream(loop, state, socket),
                                   upstream_to_client(loop, state, socket));
    co_return proxy_outcome {101, state.sent};
}

// A short local response, for failures before the upstream answers.
auto reply_status(eventloop::event_loop& loop, exchange& state, unsigned status)
    -> eventloop::task<proxy_outcome>
{
    (void)loop;
    std::vector<header> fields;
    for (const auto& [name, value] : state.target.settings->headers)
        fields.push_back({name, value});
    fields.push_back({"content-type", "text/plain; charset=utf-8"});
    fields.push_back({"cache-control", "no-store"});
    const auto text = std::to_string(status) + (
        status == 400 ? " bad request\n" : status == 408 ? " request timeout\n" :
        status == 413 ? " content too large\n" : status == 500 ? " internal server error\n" :
        status == 504 ? " gateway timeout\n" : " bad gateway\n");
    const auto sent = flatten_result(co_await state.response.async_send(status, fields,
        std::as_bytes(std::span(text))));
    if (!sent) co_return proxy_outcome {status, std::nullopt};
    co_return proxy_outcome {status, state.request.method() == method_type::head ? 0 : text.size()};
}

// Forwards the request; an unexpected status is answered locally.
auto forward(eventloop::event_loop& loop, exchange& state, bool secure)
    -> eventloop::task<step<proxy_outcome>>
{
    if (!valid_request_line(state.request)) co_return std::unexpected(400u);
    const auto length = state.request.content_length();
    if (length && *length > state.target.settings->proxy_max_request_body)
        co_return std::unexpected(413u);
    if (is_websocket(state.request)) {
        state.websocket_key = websocket_key();
        if (state.websocket_key.empty()) co_return std::unexpected(500u);
    }
    // Without a declared length, a first chunk tells whether a body follows.
    // A WebSocket request has no body to read before acceptance.
    std::size_t first = 0;
    if (!length && state.websocket_key.empty()) {
        const auto read = settle(co_await read_client(loop, state, body_chunk));
        if (!read) co_return std::unexpected(read.error());
        first = *read;
    }
    build_head(state, secure, length, first != 0);
    try {
        state.stream = &state.upstream.open(loop, *state.target.upstream);
    } catch (const std::exception&) {
        co_return std::unexpected(502u);
    }
    if (const auto connected = flatten_result(co_await bounded(loop, connect(loop, *state.stream),
                                                               state.timeout));
        !connected)
        co_return std::unexpected(timed_out(connected.error()) ? 504u : 502u);
    if (const auto sent = settle(co_await send_request(loop, state, length, first)); !sent)
        co_return std::unexpected(sent.error());
    if (const auto received = settle(co_await receive_head(loop, state)); !received)
        co_return std::unexpected(received.error());
    if (state.status == 101) co_return settle(co_await tunnel(loop, state));
    state.views.clear();
    for (const auto& [name, value] : state.fields) state.views.push_back({name, value});
    const auto failed = proxy_outcome {state.status, std::nullopt};
    if (!flatten_result(co_await state.response.async_start(state.status, state.views)))
        co_return failed;
    // A failure from here on abandons the response, which closes the client
    // connection on HTTP/1.1 and resets the stream on HTTP/2 and HTTP/3.
    if (!flatten_result(co_await relay_body(loop, state))) co_return failed;
    if (!flatten_result(co_await state.response.async_finish())) co_return failed;
    co_return proxy_outcome {state.status, state.request.method() == method_type::head
                                               ? 0 : state.sent};
}

} // namespace

auto client_address(const eventloop::http::request& request, std::string_view real_ip_header)
    -> std::string
{
    if (!real_ip_header.empty())
        if (const auto value = request.header_value(real_ip_header))
            if (const auto first = trim(value->substr(0, value->find(','))); !first.empty())
                return std::string(first);
    if (const auto peer = request.peer()) return format_address(*peer);
    return {};
}

auto proxy_request(eventloop::event_loop& loop, eventloop::http::request& request,
                   eventloop::http::response& response, const site& target, bool secure)
    -> eventloop::task<proxy_outcome>
{
    const auto state = std::make_unique<exchange>(request, response, target);
    const auto forwarded = settle(co_await forward(loop, *state, secure));
    if (forwarded) co_return *forwarded;
    const auto local = co_await reply_status(loop, *state, forwarded.error());
    co_return local ? *local : proxy_outcome {forwarded.error(), std::nullopt};
}

} // namespace stonegate
