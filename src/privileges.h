#pragma once

#include <string>
#include <sys/types.h>

namespace stonegate {

// The account Stonegate switches to once its listeners are open.
struct account {
    uid_t user {};
    gid_t group {};
    std::string name;
};

// Looks up user and group (default: the user's primary group). Throws
// std::invalid_argument for an unknown name, or when the process is neither
// root nor already that account.
[[nodiscard]] auto find_account(const std::string& user, const std::string& group) -> account;

// Switching runs in three steps across the worker threads, because Linux
// capabilities belong to threads: every worker calls keep_capabilities(),
// one thread calls switch_account(), which glibc applies to every thread,
// then every worker calls restore_bind_capability(). A worker can then still
// bind ports below 1024 when a certificate reload replaces its listeners.
// Elsewhere the first and last steps do nothing; macOS lets any user bind
// those ports.
auto keep_capabilities() -> void;
auto switch_account(const account& target) -> void;
auto restore_bind_capability() -> void;

} // namespace stonegate
