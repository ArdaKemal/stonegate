#include "privileges.h"

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#include <cerrno>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace stonegate {

auto find_account(const std::string& user, const std::string& group) -> account
{
    account result;
    result.name = user;
    std::vector<char> buffer(16384);
    passwd entry {};
    passwd* found = nullptr;
    if (::getpwnam_r(user.c_str(), &entry, buffer.data(), buffer.size(), &found) != 0 || !found)
        throw std::invalid_argument("unknown user " + user);
    result.user = found->pw_uid;
    result.group = found->pw_gid;
    if (!group.empty()) {
        ::group group_entry {};
        ::group* group_found = nullptr;
        if (::getgrnam_r(group.c_str(), &group_entry, buffer.data(), buffer.size(),
                         &group_found) != 0 || !group_found)
            throw std::invalid_argument("unknown group " + group);
        result.group = group_found->gr_gid;
    }
    if (::geteuid() != 0 && (::geteuid() != result.user || ::getegid() != result.group))
        throw std::invalid_argument("switching to user " + user + " needs root");
    return result;
}

auto keep_capabilities() -> void
{
#ifdef __linux__
    if (::geteuid() == 0 && ::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0)
        throw std::system_error(errno, std::generic_category(), "keep capabilities");
#endif
}

auto switch_account(const account& target) -> void
{
    if (::geteuid() != 0) return; // Already the target account.
    // Supplementary groups first, while still root; then the group, then the
    // user, so neither change can be undone.
    if (::initgroups(target.name.c_str(), target.group) != 0)
        throw std::system_error(errno, std::generic_category(), "set supplementary groups");
    if (::setgid(target.group) != 0)
        throw std::system_error(errno, std::generic_category(), "set group");
    if (::setuid(target.user) != 0)
        throw std::system_error(errno, std::generic_category(), "set user");
    if (target.user != 0 && ::setuid(0) == 0)
        throw std::runtime_error("root privileges could be regained");
}

auto restore_bind_capability() -> void
{
#ifdef __linux__
    if (::geteuid() == 0) return;
    __user_cap_header_struct header {_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2] {};
    data[0].effective = data[0].permitted = 1U << CAP_NET_BIND_SERVICE;
    // Fails when the capability was not kept, as for a non-root start; ports
    // below 1024 then stay unavailable to reloads.
    (void)::syscall(SYS_capset, &header, data);
    (void)::prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
#endif
}

} // namespace stonegate
