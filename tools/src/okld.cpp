// okld --- the ok format's tool on a build machine.
//
//   okld check <image> [--with <image it needs>]...
//                                  the convention (SPEC 12.2, 12.4); one line per violation
//   okld note <image>              the interfaces the image's imports require, written into
//                                  its requirements note
//   okld sign <image> <seed-file>  the signature note filled (Ed25519); prints the key
//   okld keygen <seed-file>        a new seed, written; prints its public key
//   okld inspect <image>           what the image is
//   okld note-source               the assembly that lays down the two notes, for the link
//
// It does not link: an image is linked by an ordinary linker (`ld.lld -shared').
import std;
import openkal.ld;
import openkal.run;

namespace {

const std::set<std::string>& surface() {
    static const std::set<std::string> names = [] {
        // The specification's surface, as libokrun binds it (generated from
        // SURFACE.txt by openkal-run's build.mcpp).
        std::set<std::string> s;
        unsigned long n = 0;
        const char* const* names = okrun_names(&n);
        for (unsigned long i = 0; i < n; ++i) s.insert(names[i]);
        return s;
    }();
    return names;
}

std::optional<std::vector<unsigned char>> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool write_file(const std::string& path, const std::vector<unsigned char>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(out);
}

std::string hex(const unsigned char* p, std::size_t n) {
    std::string s;
    for (std::size_t i = 0; i < n; ++i) s += std::format("{:02x}", p[i]);
    return s;
}

std::string interfaces(okld_u64 bits) {
    static const char* const names[] = { "abort", "stream", "memory", "env", "time", "random", "fs", "process",
                                         "task", "exec", "terminal", "net", "datagram", "space", "timeout" };
    std::string s;
    for (int b = 0; b < 15; ++b) if (bits & (1ull << b)) { if (!s.empty()) s += ' '; s += "openkal."; s += names[b]; }
    return s.empty() ? "none" : s;
}

// The names the images given with `--with' export.
std::set<std::string> g_elsewhere;

int check(const std::vector<unsigned char>& image) {
    int failures = okld_check(image.data(), image.size(),
        [](const char* n, void*) { return surface().contains(n) ? 1 : 0; },
        [](const char* n, void*) { return g_elsewhere.contains(n) ? 1 : 0; },
        [](const char* s, void*) { std::println(std::cerr, "okld: {}", s); }, nullptr);
    return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    const std::vector<std::string> args(argv + 1, argv + argc);
    auto usage = [] { std::println(std::cerr, "usage: okld check|note|inspect <image> | sign <image> <seed-file> | keygen <seed-file> | note-source"); return 2; };
    if (args.empty()) return usage();
    const auto& verb = args[0];

    if (verb == "note-source") {
        std::print("{}",
            "# The two notes of an ok image (SPEC 12.4): requirements, written by `okld note',\n"
            "# and a signature, written by `okld sign' and all zero until then.\n"
            "\t.section .note.openkal,\"a\",@note\n"
            "\t.p2align 2\n"
            "\t.long 8, 16, 1\n\t.asciz \"OPENKAL\"\n\t.long 1, 0\n\t.quad 0\n"
            "\t.p2align 2\n"
            "\t.long 8, 96, 2\n\t.asciz \"OPENKAL\"\n\t.fill 96, 1, 0\n");
        return 0;
    }
    if (verb == "keygen" && args.size() == 2) {
        std::array<unsigned char, 32> seed{};
        std::random_device rd;
        for (auto& b : seed) b = static_cast<unsigned char>(rd());
        if (!write_file(args[1], std::vector<unsigned char>(seed.begin(), seed.end()))) return 1;
        unsigned char key[32];
        okld_public_key(seed.data(), key);
        std::println("{}", hex(key, 32));
        return 0;
    }
    if (args.size() < 2) return usage();
    auto image = read_file(args[1]);
    if (!image) { std::println(std::cerr, "okld: {} cannot be read", args[1]); return 1; }

    if (verb == "check") {
        for (std::size_t i = 2; i + 1 < args.size(); i += 2) {
            if (args[i] != "--with") return usage();
            auto other = read_file(args[i + 1]);
            if (!other) { std::println(std::cerr, "okld: {} cannot be read", args[i + 1]); return 1; }
            okld_exports(other->data(), other->size(), [](const char* n, void*) { g_elsewhere.insert(n); }, nullptr);
        }
        return check(*image);
    }
    if (verb == "note") {
        okld_u64 bits = 0;
        okld_imports(image->data(), image->size(),
                     [](const char* n, void* c) { *static_cast<okld_u64*>(c) |= okld_interface_of(n); }, &bits);
        okld_why why{};
        if (okld_set_requirements(image->data(), image->size(), bits, &why) != 0) { std::println(std::cerr, "okld: {}", why.text); return 1; }
        if (!write_file(args[1], *image)) return 1;
        std::println("{}: requires {}", args[1], interfaces(bits));
        return 0;
    }
    if (verb == "sign" && args.size() == 3) {
        auto seed = read_file(args[2]);
        if (!seed || seed->size() != 32) { std::println(std::cerr, "okld: {} is not a 32-byte seed", args[2]); return 1; }
        okld_why why{};
        if (okld_sign(image->data(), image->size(), seed->data(), &why) != 0) { std::println(std::cerr, "okld: {}", why.text); return 1; }
        if (!write_file(args[1], *image)) return 1;
        unsigned char key[32];
        okld_public_key(seed->data(), key);
        std::println("{}: signed by {}", args[1], hex(key, 32));
        return 0;
    }
    if (verb == "inspect") {
        okld_info info{};
        okld_why why{};
        if (okld_read(image->data(), image->size(), &info, &why) != 0) { std::println(std::cerr, "okld: {}", why.text); return 1; }
        std::println("architecture  {}", info.machine == 62 ? "x86_64" : info.machine == 183 ? "aarch64" : "other");
        std::println("format        {}", info.has_requirements ? std::format("{}.{}", info.format_major, info.format_minor) : std::string("no requirements note"));
        std::println("requires      {}", interfaces(info.interfaces));
        unsigned char key[32];
        const int v = okld_verify(image->data(), image->size(), key);
        std::println("signature     {}", v == 1 ? "valid, by " + hex(key, 32) : v == 0 ? std::string("none") : std::string("PRESENT AND WRONG"));
        std::println("span          {:#x}", info.span);
        std::println("entry         {:#x}", info.entry);
        std::println("needs         {} image(s)", info.needed_count);
        std::vector<std::string> imports;
        okld_imports(image->data(), image->size(), [](const char* n, void* c) { static_cast<std::vector<std::string>*>(c)->push_back(n); }, &imports);
        std::println("imports       {}", imports.size());
        for (const auto& n : imports) std::println("  {}", n);
        return 0;
    }
    return usage();
}
