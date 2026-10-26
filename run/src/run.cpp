// The runner's core (SPEC clause 12.3): read the image, compare what it requires
// with what this implementation provides, verify its signature where asked,
// load it with this process's openkal beneath, and enter it.
#include <openkal.h>
#include <okld.h>
#include <okrun.h>
#include "image_abi.h"
#include "runner.h"

namespace okrun {

namespace {
image_state g_state;

struct text {
    char* out; unsigned long long cap; unsigned long long at = 0;
    text(char* o, unsigned long long c) : out(o), cap(c) { if (cap) out[0] = 0; }
    text& operator<<(const char* s) { while (s && *s && at + 1 < cap) out[at++] = *s++; if (cap) out[at] = 0; return *this; }
};

// --- the host the loader asks ---------------------------------------------------
void* reserve(okld_size n, void*) { return kal_exec_alloc(n); }
int publish(void* region, okld_size off, okld_size n, void*) { return kal_exec_publish_part(region, off, n); }
void release(void* region, okld_size n, void*) { kal_exec_free(region, n); }
okld_size granularity(void*) { return kal_exec_granularity(); }
void* resolve(const char* name, void*) { return okrun_resolve(name); }
void* allocate(okld_size n, void*) { return kal_alloc(n, 16); }
void deallocate(void* p, okld_size n, void*) { kal_free(p, n, 16); }

// A name as openkal names things: the supplied directory that is the longest
// prefix of it, and the rest. A relative name is beneath the first.
bool separator(char c) { return c == '/' || c == '\\'; }
char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool locate(const char* path, kal_dir& dir, const char*& rest) {
    const bool absolute = separator(path[0]) || (path[0] && path[1] == ':');
    if (!absolute) {
        char name[8]; kal_uintptr len = 0;
        if (kal_fs_preopen(0, &dir, name, sizeof name, &len) != kal_ok) return false;
        rest = path;
        while (rest[0] == '.' && separator(rest[1])) rest += 2;
        return true;
    }
    unsigned long best = 0;
    bool found = false;
    for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
        kal_dir d{}; char name[1024]; kal_uintptr len = 0;
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok || len == 0 || len >= sizeof name) continue;
        unsigned long k = 0;
        while (k < len && path[k] && (lower(path[k]) == lower(name[k]) || (separator(path[k]) && separator(name[k])))) ++k;
        if (k != len) continue;
        if (!separator(name[len - 1]) && path[len] && !separator(path[len])) continue;
        if (found && len <= best) continue;
        best = len; found = true; dir = d;
    }
    if (!found) return false;
    rest = path + best;
    while (separator(*rest)) ++rest;
    return true;
}

struct file_bytes { unsigned char* data = nullptr; unsigned long long size = 0, cap = 0; };

bool read_all(const char* path, file_bytes& out, char* why, unsigned long long cap) {
    kal_dir dir{};
    const char* rest = nullptr;
    if (!locate(path, dir, rest)) { text(why, cap) << "the image " << path << " is beneath no directory this program was given"; return false; }
    unsigned long n = 0; while (rest[n]) ++n;
    kal_file f{};
    if (kal_fs_open(dir, rest, n, KAL_OPEN_READ, &f) != kal_ok) { text(why, cap) << "the image " << path << " cannot be opened"; return false; }
    const kal_stream s = kal_fs_stream(f);
    for (;;) {
        if (out.size == out.cap) {
            const unsigned long long grown = out.cap ? out.cap * 2 : (1ull << 20);
            auto* d = static_cast<unsigned char*>(kal_alloc(grown, 16));
            if (!d) { kal_fs_close_file(f); text(why, cap) << "no memory for the image"; return false; }
            for (unsigned long long i = 0; i < out.size; ++i) d[i] = out.data[i];
            if (out.data) kal_free(out.data, out.cap, 16);
            out.data = d; out.cap = grown;
        }
        const kal_intptr got = kal_stream_read(s, out.data + out.size, out.cap - out.size);
        if (got < 0) { kal_fs_close_file(f); text(why, cap) << "the image " << path << " cannot be read"; return false; }
        if (got == 0) break;
        out.size += static_cast<unsigned long long>(got);
    }
    kal_fs_close_file(f);
    return true;
}

// An image another needs (DT_NEEDED) is found beside the image that was
// started, by its name.
char g_directory[1024];

const void* find_needed(const char* name, okld_size* size, void*) {
    char path[2048];
    unsigned long at = 0;
    for (const char* d = g_directory; *d && at + 1 < sizeof path; ++d) path[at++] = *d;
    if (at && at + 1 < sizeof path) path[at++] = '/';
    for (const char* n = name; *n && at + 1 < sizeof path; ++n) path[at++] = *n;
    path[at] = 0;
    file_bytes f;
    char why[8];
    if (!read_all(path, f, why, sizeof why)) return nullptr;
    *size = f.size;
    return f.data;
}

void release_needed(const void*, okld_size, void*) {
    // Kept: the loader's record of a module points into the image's own
    // mapping, not into these bytes, and a module needed by several is read once.
}

const char* interface_name(int bit) {
    static const char* const names[] = {
        "openkal.abort", "openkal.stream", "openkal.memory", "openkal.env", "openkal.time",
        "openkal.random", "openkal.fs", "openkal.process", "openkal.task", "openkal.exec",
        "openkal.terminal", "openkal.net", "openkal.datagram", "openkal.space", "openkal.timeout",
    };
    return bit < 15 ? names[bit] : "an interface this runner does not know";
}

using image_function = void (OKRUN_IMAGE_ABI*)(void);
using image_main = int (OKRUN_IMAGE_ABI*)(void);
void call_image(void* fn, void*) { reinterpret_cast<image_function>(fn)(); }

}  // namespace

image_state& state() { return g_state; }

}  // namespace okrun

using namespace okrun;

extern "C" void* okrun_resolve(const char* name) {
    unsigned long n = 0;
    const binding* t = bindings(n);
    for (unsigned long i = 0; i < n; ++i) if (same(t[i].name, name)) return t[i].address;
    t = space_bindings(n);
    for (unsigned long i = 0; t && i < n; ++i) if (same(t[i].name, name)) return t[i].address;
    return nullptr;
}

extern "C" int okrun_run_bytes(const void* bytes, unsigned long long size, const char* name,
                               int argc, const char* const* argv, const okrun_options* options,
                               char* why, unsigned long long cap) {
    okld_info info{};
    okld_why reason{};
    if (okld_read(bytes, size, &info, &reason) != 0) { text(why, cap) << name << ": " << reason.text; return -1; }
    if (!info.has_requirements) { text(why, cap) << name << ": no requirements note (SPEC 12.4); not an image"; return -1; }
    if (info.format_major > OKLD_FORMAT_MAJOR) { text(why, cap) << name << ": written to a later version of the format than this runner reads"; return -1; }

    // WHAT THE IMAGE REQUIRES, AGAINST WHAT THIS IMPLEMENTATION PROVIDES: the
    // loader reports at load what a linker reports at link (SPEC 12.4).
    unsigned long long provided = kal_interfaces();
    unsigned long n = 0;
    if (!space_bindings(n) || n == 0) provided &= ~(1ull << 13);
    if (const unsigned long long missing = info.interfaces & ~provided) {
        text t(why, cap);
        t << name << " requires";
        for (int bit = 0; bit < 64; ++bit) if (missing & (1ull << bit)) t << " " << interface_name(bit);
        t << ", which this system's openkal does not provide";
        return -1;
    }

    // THE SIGNATURE, where it is asked for.
    if (options && (options->require_signature || options->trusted_count)) {
        unsigned char key[32] = {};
        const int v = okld_verify(bytes, size, key);
        if (v < 0) { text(why, cap) << name << ": its signature does not hold"; return -1; }
        if (v == 0) { text(why, cap) << name << ": it is not signed, and a signature is required"; return -1; }
        if (options->trusted_count) {
            bool trusted = false;
            for (unsigned i = 0; i < options->trusted_count && !trusted; ++i) {
                bool same_key = true;
                for (int k = 0; k < 32; ++k) if (options->trusted[i * 32 + k] != key[k]) { same_key = false; break; }
                trusted = same_key;
            }
            if (!trusted) { text(why, cap) << name << ": it is signed by a key that is not trusted"; return -1; }
        }
    }

    state().argc = argc;
    state().argv = argv;
    state().name = name;

    okld_host host{};
    host.reserve = &reserve; host.publish = &publish; host.release = &release;
    host.granularity = &granularity; host.resolve = &resolve;
    host.alloc = &allocate; host.free = &deallocate;
    host.find_needed = &find_needed; host.release_bytes = &release_needed;
    {
        unsigned long last = 0, k = 0;
        for (; name[k] && k + 1 < sizeof g_directory; ++k) { g_directory[k] = name[k]; if (name[k] == '/' || name[k] == '\\') last = k; }
        g_directory[last] = 0;
        if (last == 0 && !(name[0] == '/' || name[0] == '\\')) { g_directory[0] = '.'; g_directory[1] = 0; }
    }
    host.debugger = options ? options->debugger : 0;
    okld_module* m = nullptr;
    if (okld_load(bytes, size, name, &host, &m, &reason) != 0) { text(why, cap) << name << ": " << reason.text; return -1; }
    void* entry = okld_entry(m);
    if (!entry) { text(why, cap) << name << ": the image has no entry"; return -1; }
    okld_initialise(m, &call_image, nullptr);
    const int status = reinterpret_cast<image_main>(entry)();
    okld_finalise(m, &call_image, nullptr);
    kal_exit(status);
}

extern "C" int okrun_run_file(const char* path, int argc, const char* const* argv,
                              const okrun_options* options, char* why, unsigned long long cap) {
    file_bytes f;
    if (!read_all(path, f, why, cap)) return -1;
    return okrun_run_bytes(f.data, f.size, path, argc, argv, options, why, cap);
}
