#pragma once

#include "configuration.h"

#include "eventloop/tls_context.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <memory>
#include <string>

namespace stonegate {

// One server's TLS state. The HTTP/3 listener reads its key from a file
// path, so an encrypted key is decrypted here and handed over through a
// pipe; quic_key then holds that unencrypted PEM text, wiped on destruction.
struct server_credentials {
    std::shared_ptr<eventloop::tls_context> context;
    std::string quic_key;

    server_credentials() = default;
    server_credentials(const server_credentials&) = delete;
    auto operator=(const server_credentials&) -> server_credentials& = delete;
    ~server_credentials();
};

// Credentials for every configured server, by configuration index. Loading
// reads every certificate and key file, so a reload either replaces all of
// them or none.
struct credentials {
    std::array<server_credentials, max_servers> servers;
};

[[nodiscard]] auto load_credentials(const configuration& configuration)
    -> std::shared_ptr<const credentials>;

// The private key path for an HTTP/3 listener: the configured file, or a
// /dev/fd path to a pipe holding the decrypted key, which the listener
// constructor reads once. Keep the object alive until the listener exists.
class quic_key_source {
public:
    quic_key_source(const server_config& settings, const server_credentials& loaded);

    [[nodiscard]] auto path() const noexcept -> const std::string& { return path_; }

private:
    eventloop::unique_fd pipe_;
    std::string path_;
};

} // namespace stonegate
