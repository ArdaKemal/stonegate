#include "workers.h"

#include "static_files.h"

#include <pthread.h>
#include <signal.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <iostream>
#include <latch>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace stonegate {
namespace {

// One worker per event-loop thread. A loop that leaves run() (on a signal or
// a startup failure) asks every other loop to stop through post(); the posted
// task runs on its own loop and ignores a loop that is already stopping, so a
// stop never cuts another loop's shutdown short. No loop is destroyed until
// every worker has finished posting.
struct worker {
    eventloop::event_loop* loop {nullptr};
    worker_listeners* listeners {nullptr}; // owner loop thread only
    bool stopping {false};                 // owner loop thread only
};

struct worker_group {
    explicit worker_group(std::size_t count)
        : workers(count), created(static_cast<std::ptrdiff_t>(count)),
          built(static_cast<std::ptrdiff_t>(count)), kept(static_cast<std::ptrdiff_t>(count)),
          switched(static_cast<std::ptrdiff_t>(count)),
          finished(static_cast<std::ptrdiff_t>(count)) {}
    std::vector<worker> workers;
    std::latch created; // every loop exists, so handoff targets are known
    std::latch built;
    std::latch kept;     // account switch only: every worker kept its capabilities
    std::latch switched; // account switch only: worker 0 switched the process
    std::latch finished;
    std::atomic<bool> failed {false};
    std::mutex error_mutex;
    std::string error;
    // Reloads post to worker loops only while every loop is running.
    std::mutex reload_mutex;
    bool reloads_open {false};

    auto fail(std::string message) -> void
    {
        const std::lock_guard lock {error_mutex};
        if (error.empty()) error = std::move(message);
        failed.store(true);
    }
    // Counts down for a worker that never runs a loop.
    auto absent(std::ptrdiff_t count) -> void
    {
        for (auto* latch : {&created, &built, &kept, &switched, &finished}) latch->count_down(count);
    }
    auto close_reloads() -> void
    {
        const std::lock_guard lock {reload_mutex};
        reloads_open = false;
    }
    auto stop_others(std::size_t self) -> void
    {
        for (std::size_t index = 0; index < workers.size(); ++index) {
            auto& target = workers[index];
            if (index == self || target.loop == nullptr) continue;
            // A full queue falls back to a direct stop, which could end
            // that worker's shutdown early but cannot leave it running.
            if (!target.loop->post([&target]() noexcept {
                    if (!target.stopping) target.loop->stop();
                }))
                target.loop->stop();
        }
    }
    // Hands a new generation to every worker's own loop.
    auto reload(std::shared_ptr<const generation> next) -> bool
    {
        const std::lock_guard lock {reload_mutex};
        if (!reloads_open) return false;
        for (auto& target : workers) {
            if (target.loop == nullptr) continue;
            if (!target.loop->post([&target, next]() noexcept {
                    if (!target.stopping && target.listeners) target.listeners->reload(*next);
                }))
                std::cerr << "stonegate: a worker's queue is full; it keeps its old certificates\n";
        }
        return true;
    }
};

struct worker_setup {
    const stonegate::configuration& configuration;
    std::span<const std::unique_ptr<listener_group>> groups;
    std::shared_ptr<const generation> initial;
    const std::optional<account>& target;
    eventloop::event_loop_options loop_options;
};

auto watch_drain(eventloop::event_loop& loop, eventloop::event_loop::clock::time_point deadline)
    -> eventloop::task<void>
{
    using namespace std::chrono_literals;
    while (active_requests() != 0 && eventloop::event_loop::clock::now() < deadline)
        if (co_await eventloop::sleep_for(loop, 20ms) != eventloop::timer_wait_result::expired) break;
    loop.stop();
}

// Stops accepting, then runs the loop until its in-flight requests finish,
// the deadline passes, or another signal arrives.
auto drain(eventloop::event_loop& loop, worker_listeners& listeners, int seconds) -> void
{
    listeners.close_tcp();
    if (seconds == 0 || active_requests() == 0) return;
    const auto deadline = eventloop::event_loop::clock::now() + std::chrono::seconds {seconds};
    if (loop.spawn(watch_drain(loop, deadline)) == eventloop::task_spawn_result::accepted)
        (void)loop.run();
}

auto switch_accounts(worker_group& group, const account& target, std::size_t index) -> void
{
    const auto attempt = [&](auto step) {
        if (group.failed.load()) return;
        try { step(); }
        catch (const std::exception& error) { group.fail(error.what()); }
    };
    attempt(keep_capabilities);
    group.kept.arrive_and_wait();
    if (index == 0) attempt([&] { switch_account(target); });
    group.switched.arrive_and_wait();
    attempt(restore_bind_capability);
}

// started() runs once the loop exists; worker 0 uses it to start the other
// threads, which then inherit the signal mask that loop installed.
template<typename Started>
auto run_worker(worker_group& group, const worker_setup& setup, std::size_t index,
                Started started) -> void
{
    std::optional<eventloop::event_loop> loop;
    try {
        loop.emplace(setup.loop_options);
    } catch (const std::exception& error) {
        group.fail(error.what());
        started();
        group.absent(1);
        return;
    }
    auto& self = group.workers[index];
    self.loop = &*loop;
    started();
    group.created.arrive_and_wait();
    const bool handoff = setup.configuration.workers > 1 &&
        setup.configuration.mode == worker_mode::handoff;
    std::vector<eventloop::event_loop*> serving;
    if (handoff)
        for (const auto& other : group.workers) serving.push_back(other.loop);
    worker_listeners listeners(*loop, setup.configuration, setup.groups, index, std::move(serving));
    self.listeners = &listeners;
    if (!group.failed.load() && (!handoff || index == 0)) {
        try {
            listeners.start(*setup.initial);
            if (index == 0) std::cout.flush();
        } catch (const std::exception& error) {
            group.fail(error.what());
        }
    }
    group.built.arrive_and_wait();
    if (setup.target) switch_accounts(group, *setup.target, index);
    if (index == 0 && !group.failed.load()) {
        const std::lock_guard lock {group.reload_mutex};
        group.reloads_open = true;
    }
    if (!group.failed.load()) (void)loop->run();
    self.stopping = true;
    group.close_reloads();
    group.stop_others(index);
    if (!group.failed.load()) drain(*loop, listeners, setup.configuration.shutdown_seconds);
    listeners.stop();
    self.listeners = nullptr;
    // Other workers may still post to this loop until they arrive here.
    group.finished.arrive_and_wait();
}

// Waits for SIGHUP, which the caller blocked in every thread, and reloads.
// Waking it with a SIGHUP after setting exiting ends it.
auto run_reloads(worker_group& group, const worker_setup& setup, access_logs& logs,
                 const std::atomic<bool>& exiting) -> void
{
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGHUP);
    for (;;) {
        int signal = 0;
        if (::sigwait(&signals, &signal) != 0 || exiting.load()) return;
        logs.reopen();
        try {
            auto next = make_generation(setup.configuration, setup.groups,
                                        load_credentials(setup.configuration));
            if (group.reload(std::move(next)))
                std::cerr << "stonegate: reloaded certificates and reopened access logs\n";
        } catch (const std::exception& error) {
            std::cerr << "stonegate: reload failed; keeping the old certificates: "
                      << error.what() << '\n';
        }
    }
}

} // namespace

auto run_workers(const configuration& configuration,
                 std::span<const std::unique_ptr<listener_group>> groups,
                 std::shared_ptr<const generation> initial, access_logs& logs,
                 const std::optional<account>& target) -> std::string
{
    // Preserve the original per-server frame budget even with HTTP/3
    // disabled, and sum it across servers for each loop's shared capacity.
    std::size_t connections = 0, requests = 0;
    for (const auto& settings : configuration.servers) {
        connections += settings.http3_connections;
        requests += settings.http3_requests == 0 ? settings.http3_connections * 10
                                               : settings.http3_requests;
    }
    worker_setup setup {configuration, groups, std::move(initial), target, {}};
    auto& capacities = setup.loop_options.coroutine_frame_capacities;
    for (auto& capacity : capacities) capacity = std::max(capacity, connections * 8);
    // Request handlers, file sends, and HTTP/3 request scratch use the two
    // largest frame classes.
    capacities[4] = std::max<std::size_t>({capacities[4], requests, 8192});
    capacities[5] = std::max<std::size_t>(capacities[5], 2048);

    worker_group group(configuration.workers);
    std::atomic<bool> exiting {false};
    std::thread reloads([&] { run_reloads(group, setup, logs, exiting); });
    std::vector<std::jthread> threads;
    threads.reserve(configuration.workers - 1);
    run_worker(group, setup, 0, [&] {
        for (std::size_t index = 1; index < configuration.workers; ++index) {
            try {
                threads.emplace_back([&group, &setup, index] {
                    run_worker(group, setup, index, [] {});
                });
            } catch (const std::exception& error) {
                group.fail(error.what());
                group.absent(static_cast<std::ptrdiff_t>(configuration.workers - index));
                return;
            }
        }
    });
    threads.clear();
    exiting.store(true);
    (void)::pthread_kill(reloads.native_handle(), SIGHUP);
    reloads.join();
    return group.error;
}

} // namespace stonegate
