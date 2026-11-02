#pragma once

#include "site.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/task.h"

#include <cstdint>
#include <optional>

namespace stonegate {

struct proxy_outcome {
    unsigned status {502};
    // Body bytes sent to the client, or empty when the response failed.
    std::optional<std::uint64_t> bytes;
};

// Forwards a request to the site's HTTP/1.1 upstream over a new connection
// and streams the response back. The request keeps its method, target, and
// fields, minus connection-specific ones; the upstream also receives
// X-Forwarded-Proto and X-Forwarded-Host. Client X-Forwarded-For, Forwarded,
// and X-Real-IP fields pass only when real_ip_header is set. Request bodies
// above proxy_max_request_body answer 413. An unreachable or invalid upstream
// answers 502, and a connect or response head timeout 504. A failure after
// the response has started abandons it. The site's headers replace upstream
// fields of the same name.
[[nodiscard]] auto proxy_request(eventloop::event_loop& loop, eventloop::http::request& request,
                                 eventloop::http::response& response, const site& target,
                                 bool secure) -> eventloop::task<proxy_outcome>;

} // namespace stonegate
