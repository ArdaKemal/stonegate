// Stonegate's request-facing parsing, with its invariants checked:
// percent-decoding and component-wise opening below a document root (which
// holds a symbolic link out of it), Host matching against exact and wildcard
// server names, Accept-Encoding, conditional and range selection, and the
// log, HTML, and URL escapers. Input fields are separated by newlines.
#include "../src/static_files.cc" // Its helpers live in an anonymous namespace.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>

namespace {

struct root_directory {
    std::string path;
    int descriptor {-1};
};

auto root() -> const root_directory&
{
    static const root_directory value = [] {
        char path[] = "/tmp/stonegate-fuzz-XXXXXX";
        if (::mkdtemp(path) == nullptr) std::abort();
        const std::string base = path;
        std::ofstream(base + "/index.html") << "index";
        ::mkdir((base + "/dir").c_str(), 0755);
        std::ofstream(base + "/dir/a b.txt") << "spaced";
        if (::symlink("/etc", (base + "/escape").c_str()) != 0) std::abort();
        if (::symlink("/etc/passwd", (base + "/dir/passwd").c_str()) != 0) std::abort();
        const int descriptor = ::open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (descriptor < 0) std::abort();
        char resolved[PATH_MAX];
        if (::realpath(path, resolved) == nullptr) std::abort();
        return root_directory {resolved, descriptor};
    }();
    return value;
}

auto check(bool condition) -> void
{
    if (!condition) std::abort();
}

// Whether an open descriptor names something inside the document root.
auto inside_root(int descriptor) -> bool
{
    char link[64], target[PATH_MAX];
    std::snprintf(link, sizeof(link), "/proc/self/fd/%d", descriptor);
    const auto size = ::readlink(link, target, sizeof(target) - 1);
    if (size < 0) return true; // No procfs: nothing to compare.
    const std::string_view resolved(target, static_cast<std::size_t>(size));
    const std::string_view base = root().path;
    return resolved == base || (resolved.starts_with(base) && resolved[base.size()] == '/');
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    using namespace stonegate;
    std::vector<std::string_view> parts;
    std::string_view text(reinterpret_cast<const char*>(data), size);
    while (parts.size() < 8) {
        const auto newline = text.find('\n');
        parts.push_back(text.substr(0, newline));
        if (newline == std::string_view::npos) break;
        text.remove_prefix(newline + 1);
    }
    parts.resize(8);

    if (const auto decoded = decode_path(parts[0])) {
        std::string_view rest = *decoded;
        while (!rest.empty()) {
            const auto slash = rest.find('/');
            check(rest.substr(0, slash) != "..");
            rest = slash == std::string_view::npos ? std::string_view {} : rest.substr(slash + 1);
        }
        check(decoded->find('\0') == std::string::npos);
        if (const auto opened = open_below(root().descriptor, *decoded))
            check(inside_root(opened->file.get()));
    }

    (void)accepts(parts[1], "gzip");
    (void)accepts(parts[1], "br");

    // Server names as configuration validation admits them.
    const auto name = parts[3];
    const bool valid_name = !name.empty() && name.size() <= 253 && name.front() != '.' &&
        name.back() != '.' && !name.contains("..") &&
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-.") == std::string_view::npos;
    server_config exact, wildcard, fallback;
    exact.server_names = {"example.com"};
    wildcard.server_names = {"*.example.com"};
    if (valid_name) {
        exact.server_names.emplace_back(name);
        wildcard.server_names.push_back("*." + std::string(name));
    }
    std::array<site, 3> members;
    members[0].settings = &exact;
    members[1].settings = &wildcard;
    members[2].settings = &fallback;
    site_group group;
    for (auto& member : members) group.sites.push_back(std::move(member));
    group.fallback = 2;
    (void)group.select(parts[2]);
    // Redirects build a URL from named_host: it must stay a plain host name.
    const auto host = group.named_host(parts[2]);
    check(host.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789.-_") ==
          std::string::npos);
    if (valid_authority(parts[2]))
        check(parts[2].find_first_of("/?#@\\ \t\r\n") == std::string_view::npos);

    file_info info;
    info.kind = file_info::type::regular;
    info.size = size;
    info.modified = static_cast<std::int64_t>(size) * 7919;
    const auto selected = select_file_response(info, {parts[4], parts[5], parts[6], {}});
    if (selected.status == 206)
        check(selected.length != 0 && selected.offset < info.size &&
              selected.length <= info.size - selected.offset);
    if (selected.status == 200) check(selected.offset == 0 && selected.length == info.size);

    std::string escaped;
    append_escaped(escaped, parts[7]);
    check(escaped.find_first_of("\"\n\r") == std::string::npos);
    escaped.clear();
    append_html_escaped(escaped, parts[7]);
    check(escaped.find_first_of("<>\"") == std::string::npos);
    escaped.clear();
    append_url_encoded(escaped, parts[7]);
    check(escaped.find_first_of(" \"<>\n") == std::string::npos);
    return 0;
}
