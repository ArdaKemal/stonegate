#pragma once

#include "access_log.h"
#include "configuration.h"
#include "listeners.h"
#include "privileges.h"

#include <memory>
#include <optional>
#include <span>
#include <string>

namespace stonegate {

// Runs one event loop per configured worker, the calling thread being worker
// 0, until SIGINT or SIGTERM or a startup failure stops them. Once every
// listener is open the process switches to target, if set. SIGHUP reloads
// every certificate and reopens the access logs; the caller blocks SIGHUP in
// every thread before calling. On a stop each worker closes its TCP
// listeners, lets in-flight requests finish for up to shutdown_seconds (a
// second signal ends the wait), then closes everything. Returns the first
// startup error, or an empty string after a clean stop.
auto run_workers(const configuration& configuration,
                 std::span<const std::unique_ptr<listener_group>> groups,
                 std::shared_ptr<const generation> initial, access_logs& logs,
                 const std::optional<account>& target) -> std::string;

} // namespace stonegate
