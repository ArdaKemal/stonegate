#include "access_log.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <system_error>
#include <utility>

namespace stonegate {
namespace {

[[nodiscard]] auto open_append(const std::string& path) -> eventloop::unique_fd
{
    if (path == "-") return eventloop::unique_fd(::fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0));
    return eventloop::unique_fd(::open(path.c_str(),
        O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640));
}

auto write_all(int descriptor, std::string_view text) noexcept -> bool
{
    while (!text.empty()) {
        const auto written = ::write(descriptor, text.data(), text.size());
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        text.remove_prefix(static_cast<std::size_t>(written));
    }
    return true;
}

} // namespace

access_log::access_log(std::string path) : path_(std::move(path)), file_(open_append(path_))
{
    if (!file_) throw std::system_error(errno, std::generic_category(), "open access log " + path_);
}

auto access_log::append(std::string_view line) noexcept -> void
{
    const std::lock_guard lock {mutex_};
    if (pending_.size() + line.size() > max_pending) {
        ++dropped_;
        return;
    }
    try { pending_.append(line); }
    catch (...) { ++dropped_; }
}

auto access_log::flush() noexcept -> void
{
    std::size_t dropped = 0;
    {
        const std::lock_guard lock {mutex_};
        writing_.swap(pending_);
        dropped = std::exchange(dropped_, 0);
    }
    if (!writing_.empty() && !write_all(file_.get(), writing_))
        std::fprintf(stderr, "stonegate: cannot write access log %s\n", path_.c_str());
    writing_.clear();
    if (dropped != 0)
        std::fprintf(stderr, "stonegate: access log %s buffer full; dropped %zu lines\n",
                     path_.c_str(), dropped);
}

auto access_log::reopen() noexcept -> void
{
    if (path_ == "-") return;
    eventloop::unique_fd file = open_append(path_);
    if (!file) {
        std::fprintf(stderr, "stonegate: cannot reopen access log %s; keeping the old file\n",
                     path_.c_str());
        return;
    }
    file_ = std::move(file);
}

access_logs::~access_logs()
{
    if (writer_.joinable()) {
        {
            const std::lock_guard lock {mutex_};
            stopping_ = true;
        }
        wake_.notify_one();
        writer_.join();
    }
    for (auto& log : logs_) log->flush();
}

auto access_logs::open(const std::string& path) -> access_log*
{
    for (auto& log : logs_)
        if (log->path_ == path) return log.get();
    return logs_.emplace_back(std::make_unique<access_log>(path)).get();
}

auto access_logs::start() -> void
{
    if (!logs_.empty()) writer_ = std::thread([this] { run(); });
}

auto access_logs::reopen() noexcept -> void
{
    {
        const std::lock_guard lock {mutex_};
        reopen_ = true;
    }
    wake_.notify_one();
}

auto access_logs::run() noexcept -> void
{
    std::unique_lock lock {mutex_};
    while (!stopping_) {
        (void)wake_.wait_for(lock, std::chrono::milliseconds {200},
                             [this] { return stopping_ || reopen_; });
        const bool reopen = std::exchange(reopen_, false);
        lock.unlock();
        for (auto& log : logs_) {
            log->flush();
            if (reopen) log->reopen();
        }
        lock.lock();
    }
}

} // namespace stonegate
