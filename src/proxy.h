#pragma once

#include "site.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/task.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace stonegate {

struct proxy_outcome {
    unsigned status {502};
    // Body bytes sent to the client, or empty when the response failed.
    std::optional<std::uint64_t> bytes;
};

// The client address Stonegate logs and forwards: the first entry of the
// real_ip_header field when that is set and present, else the connection's
// peer address, else empty.
[[nodiscard]] auto client_address(const eventloop::http::request& request,
                                  std::string_view real_ip_header) -> std::string;

// Forwards a request to the site's HTTP/1.1 upstream over a new connection
// and streams the response back. The request keeps its method, target, and
// fields, minus connection-specific ones; the upstream also receives
// X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-For ending in the peer
// address, and X-Real-IP holding client_address(). A client's own
// X-Forwarded-For and Forwarded fields are kept only when real_ip_header is
// set, which marks Stonegate as running behind a trusted proxy. WebSocket
// requests on any protocol become HTTP/1.1 Upgrade handshakes upstream,
// with the client's subprotocol and extension offers, and, once it answers
// 101, a byte relay in both directions under the upstream's choices. Request bodies
// above proxy_max_request_body answer 413. An unreachable or invalid upstream
// answers 502, and a connect or response head timeout 504. A failure after
// the response has started abandons it. The site's headers replace upstream
// fields of the same name.
[[nodiscard]] auto proxy_request(eventloop::event_loop& loop, eventloop::http::request& request,
                                 eventloop::http::response& response, const site& target,
                                 bool secure) -> eventloop::task<proxy_outcome>;

} // namespace stonegate
