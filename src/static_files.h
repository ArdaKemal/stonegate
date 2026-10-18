#pragma once

#include "site.h"

#include "eventloop/http/router.h"

#include <cstddef>
#include <memory>

namespace stonegate {

// A router that sends every request on one listener to Stonegate: GET
// /healthz, static files for GET and HEAD, OPTIONS, and 405 for POST, PUT,
// DELETE, PATCH, and TRACE. Each request is logged to its server's access
// log. context must outlive every server using the router.
[[nodiscard]] auto make_router(const listener_context& context)
    -> std::shared_ptr<const eventloop::http::router>;

// Requests whose handler started on this thread and has not finished.
[[nodiscard]] auto active_requests() noexcept -> std::size_t;

} // namespace stonegate
