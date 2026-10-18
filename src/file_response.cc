#include "file_response.h"

#include <sys/stat.h>

#include <charconv>
#include <chrono>
#include <cstdio>
#include <ctime>

namespace stonegate {
namespace {

[[nodiscard]] auto parse_number(std::string_view text, std::uint64_t& number) noexcept -> bool
{
    if (text.empty()) return false;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    return error == std::errc {} && end == text.data() + text.size();
}

[[nodiscard]] auto trim(std::string_view text) noexcept -> std::string_view
{
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

// Only IMF-fixdate is compared; other and invalid dates are ignored.
[[nodiscard]] auto modified_since(std::string_view text, std::int64_t modified) noexcept -> bool
{
    char weekday[4] {}, month[4] {}, zone[4] {};
    std::array<char, 30> terminated {};
    if (text.size() != 29) return false;
    for (std::size_t i = 0; i < text.size(); ++i) terminated[i] = text[i];
    int day = 0, year = 0, hour = 0, minute = 0, second = 0, used = 0;
    if (std::sscanf(terminated.data(),
            "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d %3[A-Za-z]%n",
            weekday, &day, month, &year, &hour, &minute, &second, zone, &used) != 8 ||
        used != 29 || std::string_view(zone) != "GMT" || year < 1970 ||
        hour > 23 || minute > 59 || second > 59 || hour < 0 || minute < 0 || second < 0)
        return false;
    constexpr std::array<std::string_view, 12> months {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    unsigned month_number = 0;
    for (unsigned i = 0; i < months.size(); ++i)
        if (months[i] == month) { month_number = i + 1; break; }
    if (month_number == 0) return false;
    using namespace std::chrono;
    const year_month_day date {std::chrono::year {year}, std::chrono::month {month_number},
                               std::chrono::day {static_cast<unsigned>(day)}};
    if (!date.ok()) return false;
    const auto seconds = duration_cast<std::chrono::seconds>(sys_days {date}.time_since_epoch()).count()
        + hour * 3600 + minute * 60 + second;
    return modified <= seconds;
}

[[nodiscard]] auto etag_matches(std::string_view header, std::string_view etag) noexcept -> bool
{
    const auto opaque_etag = etag.starts_with("W/") ? etag.substr(2) : etag;
    while (!header.empty()) {
        const auto comma = header.find(',');
        const auto token = trim(header.substr(0, comma));
        const auto opaque = token.starts_with("W/") ? token.substr(2) : token;
        if (token == "*" || opaque == opaque_etag) return true;
        if (comma == std::string_view::npos) break;
        header.remove_prefix(comma + 1);
    }
    return false;
}

} // namespace

auto stat_file(int descriptor, file_info& info) noexcept -> bool
{
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) return false;
    info.kind = S_ISREG(status.st_mode) ? file_info::type::regular :
        S_ISDIR(status.st_mode) ? file_info::type::directory : file_info::type::other;
    info.size = status.st_size < 0 ? 0U : static_cast<std::uint64_t>(status.st_size);
    info.modified = static_cast<std::int64_t>(status.st_mtime);
#if defined(__APPLE__)
    info.modified_nanoseconds = static_cast<std::uint32_t>(status.st_mtimespec.tv_nsec);
    info.changed = static_cast<std::int64_t>(status.st_ctimespec.tv_sec);
    info.changed_nanoseconds = static_cast<std::uint32_t>(status.st_ctimespec.tv_nsec);
#else
    info.modified_nanoseconds = static_cast<std::uint32_t>(status.st_mtim.tv_nsec);
    info.changed = static_cast<std::int64_t>(status.st_ctim.tv_sec);
    info.changed_nanoseconds = static_cast<std::uint32_t>(status.st_ctim.tv_nsec);
#endif
    info.volume = static_cast<std::uint64_t>(status.st_dev);
    info.identity = static_cast<std::uint64_t>(status.st_ino);
    return true;
}

auto http_time(std::int64_t unix_seconds) -> std::string
{
    const auto time = static_cast<std::time_t>(unix_seconds);
    std::tm parts {};
    if (::gmtime_r(&time, &parts) == nullptr) return {};
    constexpr std::array<std::string_view, 7> days {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    constexpr std::array<std::string_view, 12> months {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::array<char, 40> text {};
    const int size = std::snprintf(text.data(), text.size(), "%.3s, %02d %.3s %04d %02d:%02d:%02d GMT",
        days[static_cast<std::size_t>(parts.tm_wday)].data(), parts.tm_mday,
        months[static_cast<std::size_t>(parts.tm_mon)].data(), parts.tm_year + 1900,
        parts.tm_hour, parts.tm_min, parts.tm_sec);
    return size > 0 ? std::string(text.data(), static_cast<std::size_t>(size)) : std::string {};
}

auto select_file_response(const file_info& info, file_conditions conditions) -> file_selection
{
    file_selection result;
    result.length = info.size;
    result.modified = http_time(info.modified);
    std::array<char, 160> etag {};
    const int etag_size = std::snprintf(etag.data(), etag.size(),
        "W/\"%llx-%llx-%x-%llx-%x-%llx-%llx%.*s\"",
        static_cast<unsigned long long>(info.size),
        static_cast<unsigned long long>(info.modified), info.modified_nanoseconds,
        static_cast<unsigned long long>(info.changed), info.changed_nanoseconds,
        static_cast<unsigned long long>(info.volume),
        static_cast<unsigned long long>(info.identity),
        static_cast<int>(conditions.etag_suffix.size()), conditions.etag_suffix.data());
    if (etag_size > 0 && static_cast<std::size_t>(etag_size) < etag.size())
        result.etag.assign(etag.data(), static_cast<std::size_t>(etag_size));
    if ((!conditions.if_none_match.empty() && etag_matches(conditions.if_none_match, result.etag)) ||
        (conditions.if_none_match.empty() && !conditions.if_modified_since.empty() &&
         modified_since(conditions.if_modified_since, info.modified))) {
        result.status = 304;
        return result;
    }
    auto range = trim(conditions.range);
    if (!range.starts_with("bytes=") || range.contains(',')) return result;
    range.remove_prefix(6);
    const auto hyphen = range.find('-');
    if (hyphen == std::string_view::npos || range.substr(hyphen + 1).contains('-'))
        return result;
    const auto left = range.substr(0, hyphen), right = range.substr(hyphen + 1);
    std::uint64_t first = 0, last = 0;
    if (left.empty()) {
        if (!parse_number(right, last)) return result;
        if (last == 0 || info.size == 0) result.status = 416;
        else {
            result.offset = last >= info.size ? 0 : info.size - last;
            result.length = info.size - result.offset;
        }
    } else if (parse_number(left, first) && (right.empty() || parse_number(right, last))) {
        if (first >= info.size || (!right.empty() && last < first)) result.status = 416;
        else {
            result.offset = first;
            result.length = right.empty() || last >= info.size ? info.size - first
                                                                : last - first + 1;
        }
    } else return result;
    if (result.status == 416) {
        result.content_range = "bytes */" + std::to_string(info.size);
        result.length = 0;
        return result;
    }
    result.status = 206;
    result.content_range = "bytes " + std::to_string(result.offset) + "-" +
        std::to_string(result.offset + result.length - 1) + "/" + std::to_string(info.size);
    return result;
}

} // namespace stonegate
