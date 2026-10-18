#pragma once

#include "access_log.h"
#include "configuration.h"
#include "credentials.h"
#include "site.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <vector>

namespace stonegate {

// Servers that share one set of listeners, with a router per listener kind.
// Built once before the workers start; the routers point at the contexts,
// so a group never moves.
struct listener_group {
    // Configuration index of the first server, whose listener settings and
    // credentials the group uses.
    std::size_t server {0};
    site_group sites;
    listener_context plain, secure, quic;
    std::shared_ptr<const eventloop::http::router> plain_routes, secure_routes, quic_routes;
};

// Opens every document root and access log and groups servers by listeners.
[[nodiscard]] auto build_groups(const configuration& configuration, access_logs& logs)
    -> std::vector<std::unique_ptr<listener_group>>;

// The credentials that new TLS and HTTP/3 listeners use. A reload builds a
// new generation; the HTTP/3 worker groups are new too, because a worker
// slot stays held until the listener it replaces is gone.
struct generation {
    std::shared_ptr<const credentials> loaded;
    std::array<std::shared_ptr<eventloop::quic_worker_group>, max_servers> quic_groups;
};

[[nodiscard]] auto make_generation(const configuration& configuration,
                                   std::span<const std::unique_ptr<listener_group>> groups,
                                   std::shared_ptr<const credentials> loaded)
    -> std::shared_ptr<const generation>;

// One worker's listeners. In reuse_port mode several workers share each port
// with SO_REUSEPORT; HTTP/3 connection IDs carry the worker index and the
// generation's worker group forwards packets to their owner. In handoff
// mode only worker 0 has listeners, and its TCP servers hand connections to
// every loop in serving. TLS and HTTP/3 listeners always set SO_REUSEPORT,
// so a reload can open their replacements before closing them.
class worker_listeners {
public:
    worker_listeners(eventloop::event_loop& loop, const configuration& configuration,
                     std::span<const std::unique_ptr<listener_group>> groups, std::size_t worker,
                     std::vector<eventloop::event_loop*> serving);
    ~worker_listeners();
    worker_listeners(const worker_listeners&) = delete;
    auto operator=(const worker_listeners&) -> worker_listeners& = delete;

    // Opens every listener; only worker 0 reports them. Throws on failure.
    auto start(const generation& current) -> void;
    // Replaces each TLS and HTTP/3 listener with one using current. A
    // listener whose replacement fails keeps running; the error is printed.
    // Open connections continue on the old TLS context; HTTP/3 connections
    // close with their listener.
    auto reload(const generation& current) noexcept -> void;
    // Stops accepting TCP connections; open connections continue.
    auto close_tcp() noexcept -> void;
    // Closes HTTP/3 listeners, then shuts the loop down and runs it until
    // every root has retired, so listeners may be destroyed.
    auto stop() -> void;

private:
    struct http3_listener {
        std::unique_ptr<eventloop::http::http3_server> server;
        eventloop::task_handle<void> running;
    };

    [[nodiscard]] auto options(const listener_group& group, const generation& current,
                               const std::shared_ptr<const eventloop::http::router>& routes) const
        -> eventloop::http::server_options;
    [[nodiscard]] auto open_secure(const listener_group& group, const generation& current)
        -> eventloop::tcp_acceptor*;
    [[nodiscard]] auto open_quic(const listener_group& group, const generation& current)
        -> std::unique_ptr<http3_listener>;

    eventloop::event_loop& loop_;
    const configuration& configuration_;
    std::span<const std::unique_ptr<listener_group>> groups_;
    std::size_t worker_;
    std::vector<eventloop::event_loop*> serving_;
    bool shared_;
    std::vector<eventloop::tcp_acceptor*> plain_;
    std::vector<eventloop::tcp_acceptor*> secure_;
    // HTTP/3 owners and observed handles cannot move while run() is pending.
    std::vector<std::unique_ptr<http3_listener>> quic_;
    std::vector<std::unique_ptr<http3_listener>> retired_;
};

} // namespace stonegate
