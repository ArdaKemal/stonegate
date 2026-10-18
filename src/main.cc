#include "access_log.h"
#include "configuration.h"
#include "credentials.h"
#include "listeners.h"
#include "privileges.h"
#include "workers.h"

#include <pthread.h>
#include <signal.h>

#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

auto main(int argc, char** argv) -> int
{
    try {
        // Every thread inherits this mask: the event loops take SIGINT and
        // SIGTERM, and the reload thread waits for SIGHUP. A closed log pipe
        // must not end the process.
        sigset_t signals;
        sigemptyset(&signals);
        for (const int signal : {SIGHUP, SIGINT, SIGTERM}) sigaddset(&signals, signal);
        if (::pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0)
            throw std::runtime_error("cannot block signals");
        (void)::signal(SIGPIPE, SIG_IGN);

        const auto configuration = stonegate::parse_configuration(argc, argv);
        std::optional<stonegate::account> target;
        if (!configuration.user.empty())
            target = stonegate::find_account(configuration.user, configuration.group);
        // Load every credential, document root, and access log before
        // starting any listener; --check follows this same path without
        // creating sockets or an event loop.
        auto loaded = stonegate::load_credentials(configuration);
        stonegate::access_logs logs;
        const auto groups = stonegate::build_groups(configuration, logs);
        if (configuration.check) {
            std::cout << "Configuration OK (" << configuration.servers.size() << " server(s))\n";
            return 0;
        }
        if (configuration.workers > 1) {
            if (configuration.mode == stonegate::worker_mode::reuse_port)
                std::cout << configuration.workers << " workers share every listener\n";
            else
                std::cout << configuration.workers << " workers serve TCP connections "
                             "accepted by worker 0; HTTP/3 runs on worker 0\n";
            std::cout.flush();
        }
        logs.start();
        const auto failure = stonegate::run_workers(configuration, groups,
            stonegate::make_generation(configuration, groups, std::move(loaded)), logs, target);
        if (!failure.empty()) throw std::runtime_error(failure);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "stonegate: " << error.what() << '\n';
        return 1;
    }
}
