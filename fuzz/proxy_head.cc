// Upstream response heads as the proxy parses them. Whatever parses must
// produce fields that async_start() accepts on every protocol: lowercase
// tokens, values that cannot split a field, no connection-specific fields,
// and the site's own headers replacing upstream ones. The first byte's low
// bit marks a pending WebSocket handshake, so 101 heads are checked too.
#include "../src/proxy.cc" // parse_head lives in an anonymous namespace.

#include "http/exchange.h" // eventloop's private request_access.

#include <cstdlib>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    using namespace stonegate;
    if (size == 0) return 0;
    static auto request = eventloop::http::detail::request_access::make_request();
    static auto response = eventloop::http::detail::request_access::make_response();
    static const server_config settings = [] {
        server_config value;
        value.headers = {{"x-frame-options", "DENY"}, {"strict-transport-security", "max-age=1"}};
        return value;
    }();
    static const site target = [] {
        site value;
        value.settings = &settings;
        return value;
    }();
    auto state = std::make_unique<exchange>(request, response, target);
    if (data[0] & 1) state->websocket_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const std::string_view head(reinterpret_cast<const char*>(data + 1), size - 1);
    if (!parse_head(*state, head)) return 0;
    if (state->status < 200 && state->status != 101) return 0;
    std::size_t site_fields = 0;
    for (const auto& [name, value] : state->fields) {
        if (!is_token(name) || name != lowercase(name) ||
            std::ranges::contains(dropped_response_fields, name) || !is_field_value(value) ||
            value != trim(value))
            std::abort();
        if (name == "x-frame-options" && value != "DENY") std::abort();
        if (name == "x-frame-options") ++site_fields;
    }
    if (site_fields != 1) std::abort();
    return 0;
}
