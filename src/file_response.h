#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace stonegate {

struct file_info {
    enum class type { other, regular, directory } kind {type::other};
    std::uint64_t size {0};
    std::int64_t modified {0}; // Unix seconds.
    std::uint32_t modified_nanoseconds {0};
    std::int64_t changed {0}; // Last metadata change, Unix seconds.
    std::uint32_t changed_nanoseconds {0};
    std::uint64_t volume {0};
    std::uint64_t identity {0};
};

[[nodiscard]] auto stat_file(int descriptor, file_info& info) noexcept -> bool;

// IMF-fixdate, as in Date and Last-Modified.
[[nodiscard]] auto http_time(std::int64_t unix_seconds) -> std::string;

struct file_conditions {
    std::string_view if_none_match;
    std::string_view if_modified_since;
    // Empty when the request has no single Range field.
    std::string_view range;
    // Distinguishes the ETag of a representation compressed while sending.
    std::string_view etag_suffix;
};

// The status and body slice for a file. ETags are weak and derive from size,
// nanosecond mtime/ctime, and file identity, so a same-size rewrite with a
// restored mtime still changes them. If-None-Match takes precedence over
// If-Modified-Since, and both over Range; one closed, open-ended, or suffix
// range gives 206, an unsatisfiable one 416, anything else the full 200.
struct file_selection {
    unsigned status {200};
    std::uint64_t offset {0};
    std::uint64_t length {0};
    std::string etag;
    std::string modified;
    std::string content_range;
};

[[nodiscard]] auto select_file_response(const file_info& info, file_conditions conditions)
    -> file_selection;

} // namespace stonegate
