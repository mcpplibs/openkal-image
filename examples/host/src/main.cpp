// okrun-host library <dir>/liboktwice.okso    the library's exports, called from here
// okrun-host okb <file.okb> [arguments...]     an okb run from the bytes of memory
// okrun-host images <needed.oke> <liboktwice.okso>
//                                              a group of images run from memory
#include <okrun.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

// The image's convention: System V on x86-64 whatever this system's, the
// procedure call standard on AArch64. And the image's `long', which is 64
// bits: `long long' here, which is 64 bits on every system (a `long' is 32
// on Windows).
#if defined(__x86_64__)
using twice_fn = long long (__attribute__((sysv_abi)) *)(long long);
using next_fn  = long long (__attribute__((sysv_abi)) *)();
#else
using twice_fn = long long (*)(long long);
using next_fn  = long long (*)();
#endif

std::vector<unsigned char> read(const char* path) {
    std::ifstream in(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: okrun-host library <okso> | okb <file.okb> | images <oke> <okso>\n"); return 2; }
    okrun_options options{};
    char why[512];
    if (std::strcmp(argv[1], "library") == 0) {
        okrun_library* lib = okrun_open_library(argv[2], &options, why, sizeof why);
        if (!lib) { std::fprintf(stderr, "okrun-host: %s\n", why); return 1; }
        auto twice = reinterpret_cast<twice_fn>(okrun_symbol(lib, "twice"));
        auto next = reinterpret_cast<next_fn>(okrun_symbol(lib, "next_value"));
        if (!twice || !next) { std::fprintf(stderr, "okrun-host: the library does not export twice and next_value\n"); return 1; }
        const long long a = twice(21), b = next(), c = next();
        std::printf("library: twice(21) = %lld, next_value() = %lld, %lld\n", a, b, c);
        if (okrun_symbol(lib, "absent_name")) { std::fprintf(stderr, "okrun-host: a name the library does not export was found\n"); return 1; }
        okrun_close(lib);
        okrun_library* missing = okrun_open_library("no-such-library.okso", &options, why, sizeof why);
        std::printf("absent: %s\n", missing ? "OPENED" : why);
        return a == 42 && b == 41 && c == 42 && !missing ? 0 : 1;
    }
    if (std::strcmp(argv[1], "okb") == 0) {
        const auto bytes = read(argv[2]);
        okrun_run_okb_bytes(bytes.data(), bytes.size(), nullptr, argc - 2, const_cast<const char* const*>(argv + 2),
                            &options, why, sizeof why);
        std::fprintf(stderr, "okrun-host: %s\n", why);
        return 127;
    }
    if (std::strcmp(argv[1], "images") == 0 && argc >= 4) {
        const auto app = read(argv[2]), lib = read(argv[3]);
        const okrun_image images[] = {
            { "needed.oke", app.data(), app.size() },
            { "liboktwice.okso", lib.data(), lib.size() },
        };
        okrun_run_images(images, 2, "needed.oke", 1, const_cast<const char* const*>(argv + 2), &options, why, sizeof why);
        std::fprintf(stderr, "okrun-host: %s\n", why);
        return 127;
    }
    std::fprintf(stderr, "okrun-host: unknown mode %s\n", argv[1]);
    return 2;
}
