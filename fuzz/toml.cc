// The TOML 1.1 parser used for configuration files, with its fixed node
// and string storage.
#include "../src/toml.h"

#include <array>
#include <memory>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    static const auto nodes = std::make_unique<stonegate::toml_value[]>(2048);
    static std::array<char, 64 * 1024> strings;
    (void)stonegate::parse_toml(std::string_view(reinterpret_cast<const char*>(data), size),
                                std::span(nodes.get(), 2048), strings);
    return 0;
}
