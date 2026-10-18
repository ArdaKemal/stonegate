#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace stonegate {

inline constexpr std::size_t max_servers = 16;
// A worker index is one byte of an HTTP/3 connection ID.
inline constexpr std::size_t max_workers = 256;
inline constexpr std::size_t max_server_names = 16;
inline constexpr std::size_t max_response_headers = 32;
inline constexpr std::size_t max_cache_rules = 64;
// Whether the kernel spreads connections and datagrams across sockets that
// share a port, so every worker can open its own listeners.
#ifdef __linux__
inline constexpr bool kernel_balances_reuse_port = true;
#else
inline constexpr bool kernel_balances_reuse_port = false;
#endif
#ifdef STONEGATE_ZLIB
inline constexpr bool gzip_available = true;
#else
inline constexpr bool gzip_available = false;
#endif

// A Cache-Control value for paths that start with a "/" prefix, or for
// names that end in a "*.ext" suffix.
struct cache_rule {
    std::string pattern;
    std::string value;
};

struct server_config {
    std::string name;
    std::string root;
    std::string bind = "127.0.0.1";
    std::string certificate;
    std::string private_key;
    std::string key_password;
    std::string redirect_host = "localhost";
    std::uint16_t http_port = 8080;
    std::uint16_t https_port = 8443;
    std::uint16_t http3_port = 0;
    std::size_t http3_connections = 8;
    std::size_t http3_requests = 0;
    std::size_t http3_max_datagram = 8192;
    int header_timeout_ms = 30000;
    int idle_timeout_ms = 60000;
    bool directory_listing = false;
    bool reuse_port = false;
    bool http2 = true;
    enum class http_mode { serve, redirect, off } mode = http_mode::serve;

    // Lowercase host names, or "*.example.com" wildcards, that select this
    // server among servers sharing its listeners. Empty matches any host.
    std::vector<std::string> server_names;
    // Access log path; "-" is standard output and empty disables logging.
    std::string access_log;
    // A request field holding a proxy's client address list, such as
    // x-forwarded-for; its first entry is logged as the client.
    std::string real_ip_header;
    // Serve <file>.br or <file>.gz when the client accepts that encoding.
    bool precompressed = false;
    // Compress other compressible files with gzip while sending them.
    bool gzip = false;
    std::uint64_t gzip_min_size = 1024;
    std::uint64_t gzip_max_size = 8 * 1024 * 1024;
    // Added to every Stonegate response; names are lowercase.
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<cache_rule> cache_rules;
    // Status code and a document-root path served as that error's body.
    std::vector<std::pair<unsigned, std::string>> error_pages;
};

// How several workers receive connections: each opens every listener with
// SO_REUSEPORT, or worker 0 accepts TCP connections and hands them to every
// worker while serving HTTP/3 alone. auto picks reuse_port where the kernel
// balances shared ports.
enum class worker_mode { automatic, reuse_port, handoff };

struct configuration {
    std::vector<server_config> servers;
    int shutdown_seconds = 5;
    std::size_t workers = 1;
    worker_mode mode = worker_mode::automatic;
    // Account to switch to once every listener is open; group defaults to the
    // user's primary group.
    std::string user;
    std::string group;
    bool check = false;
};

// Owns all strings; no TOML views survive loading.
auto parse_configuration(int argc, char** argv) -> configuration;

// Whether two servers can share listeners: the same bind address, ports,
// TLS credentials, protocol options, and timeouts.
[[nodiscard]] auto same_listeners(const server_config& left, const server_config& right) -> bool;

} // namespace stonegate
