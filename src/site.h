#pragma once

#include "configuration.h"

#include "eventloop/ip_endpoint.h"
#include "eventloop/unique_fd.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace stonegate {

class access_log;

// One configured server's runtime state. It is built before the workers
// start and only read afterwards, from every worker thread.
struct site {
    const server_config* settings {nullptr};
    // Open only for servers without an upstream.
    eventloop::unique_fd root;
    access_log* log {nullptr};
    std::optional<eventloop::ip_endpoint> upstream;
};

// The servers sharing one set of listeners. A request goes to the server
// whose server_names hold its host, otherwise to fallback: the server
// without server_names, or the first one.
struct site_group {
    std::vector<site> sites;
    std::size_t fallback {0};

    [[nodiscard]] auto select(std::string_view authority) const noexcept -> const site&;
    // The request host, lowercase and without port or trailing dot, when it
    // matches a server_names entry; empty otherwise.
    [[nodiscard]] auto named_host(std::string_view authority) const -> std::string;

private:
    [[nodiscard]] auto match(std::string_view host) const noexcept -> const site*;
};

// What a route handler knows about the listener that took the request.
struct listener_context {
    const site_group* sites {nullptr};
    // Whether the request arrived over TLS or QUIC; forwarded upstream.
    bool secure {false};
    // Alt-Svc value for file responses on TLS TCP listeners; empty otherwise.
    std::string alt_svc;
    // "https://redirect_host[:port]" when a plain listener redirects every
    // request, keeping its path and query; empty otherwise. A request whose
    // host matches a server name keeps that host instead.
    std::string redirect_origin;
    // ":port" after a redirect host, or empty for 443.
    std::string redirect_port;
};

} // namespace stonegate
