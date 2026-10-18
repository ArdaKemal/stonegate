#include "credentials.h"

#include <fcntl.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cerrno>
#include <memory>
#include <stdexcept>
#include <system_error>

namespace stonegate {
namespace {

struct bio_deleter { auto operator()(BIO* bio) const noexcept -> void { BIO_free(bio); } };
struct key_deleter { auto operator()(EVP_PKEY* key) const noexcept -> void { EVP_PKEY_free(key); } };

// Reads an encrypted PEM private key and returns it unencrypted.
[[nodiscard]] auto decrypt_key(const std::string& path, const std::string& password) -> std::string
{
    const std::unique_ptr<BIO, bio_deleter> input(BIO_new_file(path.c_str(), "r"));
    if (!input) throw std::invalid_argument("cannot read private key");
    const std::unique_ptr<EVP_PKEY, key_deleter> key(PEM_read_bio_PrivateKey(
        input.get(), nullptr, nullptr, const_cast<char*>(password.c_str())));
    if (!key) throw std::invalid_argument("cannot decrypt private key");
    const std::unique_ptr<BIO, bio_deleter> output(BIO_new(BIO_s_secmem()));
    if (!output || PEM_write_bio_PrivateKey(output.get(), key.get(), nullptr, nullptr, 0,
                                            nullptr, nullptr) != 1)
        throw std::runtime_error("cannot encode private key");
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(output.get(), &memory);
    return std::string(memory->data, memory->length);
}

} // namespace

server_credentials::~server_credentials()
{
    if (!quic_key.empty()) OPENSSL_cleanse(quic_key.data(), quic_key.size());
}

auto load_credentials(const configuration& configuration) -> std::shared_ptr<const credentials>
{
    auto loaded = std::make_shared<credentials>();
    for (std::size_t index = 0; index < configuration.servers.size(); ++index) {
        const auto& settings = configuration.servers[index];
        if (settings.certificate.empty()) continue;
        auto& server = loaded->servers[index];
        try {
            server.context = eventloop::tls_context::make_server(
                settings.certificate, settings.private_key, settings.key_password);
            if (settings.http3_port != 0 && !settings.key_password.empty())
                server.quic_key = decrypt_key(settings.private_key, settings.key_password);
        } catch (const std::exception& error) {
            throw std::invalid_argument("server " + settings.name + ": " + error.what());
        }
    }
    return loaded;
}

quic_key_source::quic_key_source(const server_config& settings, const server_credentials& loaded)
{
    if (loaded.quic_key.empty()) {
        path_ = settings.private_key;
        return;
    }
    int ends[2] {};
    if (::pipe(ends) != 0) throw std::system_error(errno, std::generic_category(), "key pipe");
    pipe_ = eventloop::unique_fd(ends[0]);
    const eventloop::unique_fd writer(ends[1]);
    (void)::fcntl(ends[0], F_SETFD, FD_CLOEXEC);
    (void)::fcntl(ends[1], F_SETFD, FD_CLOEXEC);
    // The key fits the pipe buffer, so a nonblocking write either completes
    // or fails rather than waiting for a reader.
    (void)::fcntl(ends[1], F_SETFL, O_NONBLOCK);
    const auto written = ::write(ends[1], loaded.quic_key.data(), loaded.quic_key.size());
    if (written != static_cast<ssize_t>(loaded.quic_key.size()))
        throw std::runtime_error("private key does not fit a pipe");
    path_ = "/dev/fd/" + std::to_string(ends[0]);
}

} // namespace stonegate
