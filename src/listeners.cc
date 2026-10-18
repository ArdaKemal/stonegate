#include "listeners.h"

#include "static_files.h"

#include "eventloop/http/server.h"

#include <fcntl.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

namespace stonegate {
namespace {

template<typename Listener>
auto serve(eventloop::event_loop& loop, Listener& listener) -> eventloop::task<void>
{
    (void)loop;
    (void)co_await listener.run();
}

template<typename Listener, typename... Args>
auto open_listener(eventloop::event_loop& loop, Args&&... args) -> eventloop::tcp_acceptor*
{
    auto listener = std::make_unique<Listener>(loop, std::forward<Args>(args)...);
    auto* active = listener.get();
    loop.add(std::move(listener));
    if (loop.spawn(serve(loop, *active)) != eventloop::task_spawn_result::accepted) {
        active->close();
        throw std::runtime_error("listener task capacity exhausted");
    }
    return active;
}

[[nodiscard]] auto group_name(const listener_group& group) -> std::string
{
    std::string names;
    for (const auto& member : group.sites.sites) {
        if (!names.empty()) names += ',';
        names += member.settings->name;
    }
    return names;
}

} // namespace

auto build_groups(const configuration& configuration, access_logs& logs)
    -> std::vector<std::unique_ptr<listener_group>>
{
    std::vector<std::unique_ptr<listener_group>> groups;
    for (std::size_t index = 0; index < configuration.servers.size(); ++index) {
        const auto& settings = configuration.servers[index];
        auto existing = std::ranges::find_if(groups, [&](const auto& group) {
            return same_listeners(configuration.servers[group->server], settings);
        });
        if (existing == groups.end()) {
            groups.push_back(std::make_unique<listener_group>());
            groups.back()->server = index;
            existing = std::prev(groups.end());
        }
        site member;
        member.settings = &settings;
        member.root = eventloop::unique_fd(::open(settings.root.c_str(),
                                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (!member.root)
            throw std::system_error(errno, std::generic_category(),
                                    "server " + settings.name + ": open root");
        if (!settings.access_log.empty()) member.log = logs.open(settings.access_log);
        (*existing)->sites.sites.push_back(std::move(member));
    }
    for (auto& group : groups) {
        auto& sites = group->sites;
        const auto fallback = std::ranges::find_if(sites.sites,
            [](const site& member) { return member.settings->server_names.empty(); });
        sites.fallback = fallback == sites.sites.end()
            ? 0 : static_cast<std::size_t>(fallback - sites.sites.begin());
        const auto& settings = configuration.servers[group->server];
        group->plain.sites = group->secure.sites = group->quic.sites = &sites;
        if (settings.http3_port != 0)
            group->secure.alt_svc = "h3=\":" + std::to_string(settings.http3_port) + "\"; ma=86400";
        if (settings.mode == server_config::http_mode::redirect) {
            group->plain.redirect_origin = "https://" + settings.redirect_host;
            if (settings.https_port != 443)
                group->plain.redirect_origin += ":" + std::to_string(settings.https_port);
        }
        group->plain_routes = make_router(group->plain);
        group->secure_routes = make_router(group->secure);
        group->quic_routes = make_router(group->quic);
    }
    return groups;
}

auto make_generation(const configuration& configuration,
                     std::span<const std::unique_ptr<listener_group>> groups,
                     std::shared_ptr<const credentials> loaded) -> std::shared_ptr<const generation>
{
    auto result = std::make_shared<generation>();
    result->loaded = std::move(loaded);
    // Endpoints sharing a port forward packets for connections another
    // worker owns, so a client whose address changes keeps its connection.
    if (configuration.workers > 1 && configuration.mode == worker_mode::reuse_port)
        for (std::size_t index = 0; index < groups.size(); ++index)
            if (configuration.servers[groups[index]->server].http3_port != 0)
                result->quic_groups[index] =
                    std::make_shared<eventloop::quic_worker_group>(configuration.workers);
    return result;
}

worker_listeners::worker_listeners(eventloop::event_loop& loop, const configuration& configuration,
                                   std::span<const std::unique_ptr<listener_group>> groups,
                                   std::size_t worker, std::vector<eventloop::event_loop*> serving)
    : loop_(loop), configuration_(configuration), groups_(groups), worker_(worker),
      serving_(std::move(serving)),
      shared_(configuration.workers > 1 && configuration.mode == worker_mode::reuse_port),
      plain_(groups.size()), secure_(groups.size()), quic_(groups.size())
{
}

worker_listeners::~worker_listeners() = default;

auto worker_listeners::options(const listener_group& group, const generation& current,
                               const std::shared_ptr<const eventloop::http::router>& routes) const
    -> eventloop::http::server_options
{
    const auto& settings = configuration_.servers[group.server];
    const auto index = static_cast<std::size_t>(
        std::ranges::find_if(groups_, [&](const auto& item) { return item.get() == &group; }) -
        groups_.begin());
    return {
        .routes = routes,
        .reuse_port = settings.reuse_port || shared_,
        .serving_loops = serving_,
        .header_timeout = std::chrono::milliseconds {settings.header_timeout_ms},
        .idle_timeout = std::chrono::milliseconds {settings.idle_timeout_ms},
        .enable_http2 = settings.http2,
        .connection_capacity = settings.http3_connections,
        .request_capacity = settings.http3_requests,
        .max_udp_payload_size = settings.http3_max_datagram,
        .worker_index = shared_
            ? std::optional<std::uint8_t> {static_cast<std::uint8_t>(worker_)}
            : std::nullopt,
        .worker_group = current.quic_groups[index],
    };
}

auto worker_listeners::open_secure(const listener_group& group, const generation& current)
    -> eventloop::tcp_acceptor*
{
    const auto& settings = configuration_.servers[group.server];
    auto listener_options = options(group, current, group.secure_routes);
    listener_options.reuse_port = true;
    return open_listener<eventloop::http::https_server>(loop_,
        eventloop::ip_endpoint::parse(settings.bind, settings.https_port),
        current.loaded->servers[group.server].context, std::move(listener_options));
}

auto worker_listeners::open_quic(const listener_group& group, const generation& current)
    -> std::unique_ptr<http3_listener>
{
    const auto& settings = configuration_.servers[group.server];
    auto listener_options = options(group, current, group.quic_routes);
    listener_options.reuse_port = true;
    const quic_key_source key(settings, current.loaded->servers[group.server]);
    auto listener = std::make_unique<http3_listener>();
    listener->server = std::make_unique<eventloop::http::http3_server>(
        loop_, eventloop::ip_endpoint::parse(settings.bind, settings.http3_port),
        settings.certificate, key.path(), std::move(listener_options));
    if (loop_.spawn(listener->server->run(), listener->running) !=
        eventloop::task_spawn_result::accepted) {
        listener->server->close();
        throw std::runtime_error("HTTP/3 listener task capacity exhausted");
    }
    return listener;
}

auto worker_listeners::start(const generation& current) -> void
{
    const bool report = worker_ == 0;
    for (std::size_t index = 0; index < groups_.size(); ++index) {
        const auto& group = *groups_[index];
        const auto& settings = configuration_.servers[group.server];
        const auto name = group_name(group);
        if (settings.mode != server_config::http_mode::off) {
            plain_[index] = open_listener<eventloop::http::server>(loop_,
                eventloop::ip_endpoint::parse(settings.bind, settings.http_port),
                options(group, current, group.plain_routes));
            if (report)
                std::cout << name << (settings.mode == server_config::http_mode::redirect
                                          ? ": HTTP redirect on " : ": HTTP/1.1 on ")
                          << settings.bind << ':' << settings.http_port << '\n';
        }
        if (current.loaded->servers[group.server].context && settings.https_port != 0) {
            secure_[index] = open_secure(group, current);
            if (report)
                std::cout << name << ": HTTPS (HTTP/1.1" << (settings.http2 ? ", HTTP/2" : "")
                          << ") on " << settings.bind << ':' << settings.https_port << '\n';
        }
        if (settings.http3_port != 0) {
            quic_[index] = open_quic(group, current);
            if (report)
                std::cout << name << ": HTTP/3 on UDP " << settings.bind << ':'
                          << settings.http3_port << '\n';
        }
    }
}

auto worker_listeners::reload(const generation& current) noexcept -> void
{
    for (std::size_t index = 0; index < groups_.size(); ++index) {
        const auto& group = *groups_[index];
        const auto name = configuration_.servers[group.server].name;
        if (secure_[index] != nullptr) {
            try {
                auto* replacement = open_secure(group, current);
                // close() frees the loop-owned listener.
                std::exchange(secure_[index], replacement)->close();
            } catch (const std::exception& error) {
                std::cerr << "stonegate: " << name << ": TLS listener kept its old certificate: "
                          << error.what() << '\n';
            }
        }
        if (quic_[index] != nullptr) {
            try {
                auto replacement = open_quic(group, current);
                auto old = std::exchange(quic_[index], std::move(replacement));
                old->server->close();
                retired_.push_back(std::move(old));
            } catch (const std::exception& error) {
                std::cerr << "stonegate: " << name << ": HTTP/3 listener kept its old certificate: "
                          << error.what() << '\n';
            }
        }
    }
}

auto worker_listeners::close_tcp() noexcept -> void
{
    for (auto* listeners : {&plain_, &secure_})
        for (auto*& listener : *listeners)
            if (listener != nullptr) std::exchange(listener, nullptr)->close();
}

auto worker_listeners::stop() -> void
{
    for (auto* listeners : {&quic_, &retired_})
        for (auto& listener : *listeners)
            if (listener) listener->server->close();
    loop_.shutdown(eventloop::event_loop::clock::duration::zero());
    while (loop_.run() != eventloop::event_loop_result::stopped)
        loop_.shutdown(eventloop::event_loop::clock::duration::zero());
    // A stopped, shutting-down loop has retired all roots, including endpoint
    // receivers and connection tasks. Owners/handles may now be destroyed.
}

} // namespace stonegate
