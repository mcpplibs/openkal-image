// okrun --- runs an ok image, or an okb (docs/okb.md): `okrun [options] image
// [arguments...]'. An okb runs this machine's architecture's entry.
//
//   --require-signature   refuse an image that is not signed
//   --trust <hex>         a public key (64 hexadecimal digits) whose images run;
//                         given at least once, an image signed by another is refused
//   --debugger            announce the image to gdb and lldb (GDB JIT interface)
//
// The image is told its arguments are the image's (or the okb's) name and what
// follows it. The images it needs are found beside it, in `lib/<arch>/' and
// `lib/' there, and in OKRUN_PATH.
#include <okrun.h>
#include <openkal.h>

namespace {
unsigned long length(const char* s) { unsigned long n = 0; while (s && s[n]) ++n; return n; }
void say(const char* s) { kal_stream_write(kal_stderr(), s, length(s)); }
bool same(const char* a, const char* b) { for (;; ++a, ++b) { if (*a != *b) return false; if (!*a) return true; } }
int hex(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
}  // namespace

int main(int argc, char** argv) {
    okrun_options options{};
    static unsigned char keys[16 * 32];
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1] == '-'; ++i) {
        if (same(argv[i], "--")) { ++i; break; }
        if (same(argv[i], "--require-signature")) { options.require_signature = 1; continue; }
        if (same(argv[i], "--debugger")) { options.debugger = 1; continue; }
        if (same(argv[i], "--trust") && i + 1 < argc && options.trusted_count < 16 && length(argv[i + 1]) == 64) {
            const char* k = argv[++i];
            for (int b = 0; b < 32; ++b) {
                const int hi = hex(k[2 * b]), lo = hex(k[2 * b + 1]);
                if (hi < 0 || lo < 0) { say("okrun: --trust takes 64 hexadecimal digits\n"); return 2; }
                keys[options.trusted_count * 32 + b] = static_cast<unsigned char>(hi * 16 + lo);
            }
            ++options.trusted_count;
            continue;
        }
        say("okrun: unknown option "); say(argv[i]); say("\n");
        return 2;
    }
    options.trusted = keys;
    if (i >= argc) {
        say("usage: okrun [--require-signature] [--trust <hex>]... [--debugger] image|okb [arguments...]\n");
        return 2;
    }
    char why[512];
    okrun_run_file(argv[i], argc - i, const_cast<const char* const*>(argv + i), &options, why, sizeof why);
    say("okrun: "); say(why); say("\n");
    return 127;
}
