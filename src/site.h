#pragma once

#include "configuration.h"

#include "eventloop/unique_fd.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace stonegate {

class access_log;

// One configured server's runtime state. It is built before the workers
// start and only read afterwards, from every worker thread.
struct site {
    const server_config* settings {nullptr};
    eventloop::unique_fd root;
    access_log* log {nullptr};
};

// The servers sharing one set of listeners. A request goes to the server
// whose server_names hold its host, otherwise to fallback: the server
// without server_names, or the first one.
struct site_group {
    std::vector<site> sites;
    std::size_t fallback {0};

    [[nodiscard]] auto select(std::string_view authority) const noexcept -> const site&;
};

// What a route handler knows about the listener that took the request.
struct listener_context {
    const site_group* sites {nullptr};
    // Alt-Svc value for file responses on TLS TCP listeners; empty otherwise.
    std::string alt_svc;
    // "https://host[:port]" when a plain listener redirects every request
    // there, keeping its path and query; empty otherwise.
    std::string redirect_origin;
};

} // namespace stonegate
