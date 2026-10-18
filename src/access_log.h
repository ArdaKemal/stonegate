#pragma once

#include "eventloop/unique_fd.h"

#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace stonegate {

// One access log file, shared by every worker. Workers append whole lines
// under a lock without touching the disk; the writer thread of access_logs
// writes them out. A line that would grow the pending text past 4 MiB is
// dropped and counted, so a stalled disk cannot block request handling.
class access_log {
public:
    static constexpr std::size_t max_pending = 4 * 1024 * 1024;

    // path "-" writes to standard output.
    explicit access_log(std::string path);

    auto append(std::string_view line) noexcept -> void;

private:
    friend class access_logs;
    // Writer thread only.
    auto flush() noexcept -> void;
    auto reopen() noexcept -> void;

    std::string path_;
    eventloop::unique_fd file_;
    std::mutex mutex_;
    std::string pending_;
    std::string writing_;
    std::size_t dropped_ {0};
};

// The open access logs and the thread that writes them, at least every
// 200 ms. reopen() makes the writer reopen every file by path after the
// next flush, for log rotation.
class access_logs {
public:
    access_logs() = default;
    ~access_logs();
    access_logs(const access_logs&) = delete;
    auto operator=(const access_logs&) -> access_logs& = delete;

    // Opens path for appending, once per path. Call before start().
    [[nodiscard]] auto open(const std::string& path) -> access_log*;
    auto start() -> void;
    auto reopen() noexcept -> void;

private:
    auto run() noexcept -> void;

    std::vector<std::unique_ptr<access_log>> logs_;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_ {false};
    bool reopen_ {false};
    std::thread writer_;
};

} // namespace stonegate
