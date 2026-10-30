// The runner's core (SPEC clause 12.3): read the image, compare what it requires
// with what this implementation provides, verify its signature where asked,
// load it with this process's openkal beneath, and enter it.
//
// Where an image comes from: a file; the bytes of one in memory; a member of an
// okb or of any archive of images (docs/okb.md), read in place from a file read
// once or from bytes a program carries; one of a group of images in memory. The
// images it needs are found by one search, in one order, whichever it was:
//
//   1. the group, or the archive --- this architecture's directory, then its root;
//   2. beside the image (or the archive, or the program that carries it), then
//      `lib/<arch>/' and `lib/' there;
//   3. each directory of OKRUN_PATH, `<dir>/<arch>/' then `<dir>/'.
//
// A library (`okrun_open_library') is an image whose exports a program of this
// system calls (part 2 design §8): found by the same search, beginning beside
// the program.
#include <openkal.h>
#include <okld.h>
#include <okrun.h>
#include "image_abi.h"
#include "runner.h"

namespace okrun {

namespace {
image_state g_state;

using u64 = unsigned long long;

struct text {
    char* out; unsigned long long cap; unsigned long long at = 0;
    text(char* o, unsigned long long c) : out(o), cap(c) { if (cap) out[0] = 0; }
    text& operator<<(const char* s) { while (s && *s && at + 1 < cap) out[at++] = *s++; if (cap) out[at] = 0; return *this; }
};

unsigned long length(const char* s) { unsigned long n = 0; while (s && s[n]) ++n; return n; }
void copy_text(char* d, unsigned long cap, const char* s) {
    unsigned long i = 0;
    for (; s && s[i] && i + 1 < cap; ++i) d[i] = s[i];
    if (cap) d[i] = 0;
}
bool same_bytes(const void* a, const void* b, unsigned long n) {
    const auto* x = static_cast<const unsigned char*>(a);
    const auto* y = static_cast<const unsigned char*>(b);
    for (unsigned long i = 0; i < n; ++i) if (x[i] != y[i]) return false;
    return true;
}

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

// A file's bytes: a region of the file (openkal.map), or a buffer it was read
// into where the file cannot be mapped. `cap' is zero for a region.
struct file_bytes { unsigned char* data = nullptr; unsigned long long size = 0, cap = 0; };

void release_bytes(unsigned char* data, unsigned long long size, unsigned long long cap) {
    if (!data) return;
    if (cap == 0) kal_map_release(data, static_cast<kal_uintptr>(size));
    else kal_free(data, cap, 16);
}

void release_file(file_bytes& f) {
    release_bytes(f.data, f.size, f.cap);
    f = {};
}

// THE FILE IS MAPPED, NOT READ (openkal 0.18). An image or an okb was read
// whole into a buffer that doubled as it grew and was kept for the life of the
// program: a 71.5 MB image held 128 MiB of the heap, every page of it resident.
// A region of the file is resident only where it is touched, and its pages are
// the file's. Private and writable, so a page the loader writes is copied
// rather than refused; the file never changes.
bool map_all(kal_file f, file_bytes& out) {
    kal_node_info info{};
    info.self_size = sizeof info;
    if (kal_fs_file_info(f, KAL_INFO_SIZE, &info) != kal_ok || info.size == 0) return false;
    void* p = nullptr;
    if (kal_map_file(f, 0, static_cast<kal_uintptr>(info.size), KAL_MAP_WRITE, &p) != kal_ok) return false;
    out.data = static_cast<unsigned char*>(p);
    out.size = info.size;
    out.cap = 0;
    return true;
}

bool read_all(const char* path, file_bytes& out, char* why, unsigned long long cap) {
    kal_dir dir{};
    const char* rest = nullptr;
    if (!locate(path, dir, rest)) { text(why, cap) << path << " is beneath no directory this program was given"; return false; }
    unsigned long n = length(rest);
    kal_file f{};
    if (kal_fs_open(dir, rest, n, KAL_OPEN_READ, &f) != kal_ok) { text(why, cap) << path << " cannot be opened"; return false; }
    if (map_all(f, out)) { kal_fs_close_file(f); return true; }
    const kal_stream s = kal_fs_stream(f);
    for (;;) {
        if (out.size == out.cap) {
            const unsigned long long grown = out.cap ? out.cap * 2 : (1ull << 20);
            auto* d = static_cast<unsigned char*>(kal_alloc(grown, 16));
            if (!d) { kal_fs_close_file(f); release_file(out); text(why, cap) << "no memory for " << path; return false; }
            for (unsigned long long i = 0; i < out.size; ++i) d[i] = out.data[i];
            if (out.data) kal_free(out.data, out.cap, 16);
            out.data = d; out.cap = grown;
        }
        const kal_intptr got = kal_stream_read(s, out.data + out.size, out.cap - out.size);
        if (got < 0) { kal_fs_close_file(f); release_file(out); text(why, cap) << path << " cannot be read"; return false; }
        if (got == 0) break;
        out.size += static_cast<unsigned long long>(got);
    }
    kal_fs_close_file(f);
    return true;
}

bool is_archive(const void* bytes, unsigned long long size) {
    const auto* b = static_cast<const unsigned char*>(bytes);
    return size >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4;
}

// The directory part of a name, or "." when it has none.
void directory_of(const char* name, char* out, unsigned long cap) {
    unsigned long last = 0, k = 0;
    bool any = false;
    for (; name && name[k] && k + 1 < cap; ++k) { out[k] = name[k]; if (separator(name[k])) { last = k; any = true; } }
    if (!any) { copy_text(out, cap, "."); return; }
    out[last == 0 ? 1 : last] = 0;   // "/x" keeps its root
}

const char* interface_name(int bit) {
    static const char* const names[] = {
        "openkal.abort", "openkal.stream", "openkal.memory", "openkal.env", "openkal.time",
        "openkal.random", "openkal.fs", "openkal.process", "openkal.task", "openkal.exec",
        "openkal.terminal", "openkal.net", "openkal.datagram", "openkal.space", "openkal.timeout",
    };
    return bit < 15 ? names[bit] : "an interface this runner does not know";
}

bool key_is_trusted(const okrun_options* options, const unsigned char key[32]) {
    if (!options || !options->trusted_count) return true;
    for (unsigned i = 0; i < options->trusted_count; ++i)
        if (same_bytes(options->trusted + i * 32, key, 32)) return true;
    return false;
}

bool signature_required(const okrun_options* options) {
    return options && (options->require_signature || options->trusted_count);
}

// WHAT EVERY IMAGE IS ASKED BEFORE IT IS LOADED, whether it is entered or
// needed: that it is one, that this runner reads its version, that this
// implementation provides what it requires, and, where asked, that it is
// signed by a trusted key.
bool admit(const void* bytes, unsigned long long size, const char* name, const okrun_options* options,
           char* why, unsigned long long cap) {
    okld_info info{};
    okld_why reason{};
    if (okld_read(bytes, size, &info, &reason) != 0) { text(why, cap) << name << ": " << reason.text; return false; }
    if (!info.has_requirements) { text(why, cap) << name << ": no requirements note (SPEC 12.4); not an image"; return false; }
    if (info.format_major > OKLD_FORMAT_MAJOR) { text(why, cap) << name << ": written to a later version of the format than this runner reads"; return false; }
    if (const char* arch = okld_okb_arch_of(info.machine); !arch || !same_bytes(arch, okrun_arch, length(okrun_arch) + 1)) {
        text(why, cap) << name << ": an image of " << (arch ? arch : "another architecture") << ", and this machine is " << okrun_arch;
        return false;
    }
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
        return false;
    }
    if (signature_required(options)) {
        unsigned char key[32] = {};
        const int v = okld_verify(bytes, size, key);
        if (v < 0) { text(why, cap) << name << ": its signature does not hold"; return false; }
        if (v == 0) { text(why, cap) << name << ": it is not signed, and a signature is required"; return false; }
        if (!key_is_trusted(options, key)) { text(why, cap) << name << ": it is signed by a key that is not trusted"; return false; }
    }
    return true;
}

// --- where the images an image needs are found ----------------------------------

struct search {
    const okrun_options* options = nullptr;
    // A group of images in memory.
    const okrun_image* images = nullptr;
    unsigned long image_count = 0;
    // An archive in memory, its manifest, and this architecture's directory in it.
    const unsigned char* archive = nullptr;
    unsigned long long archive_size = 0;
    const void* json = nullptr;
    unsigned long long json_size = 0;
    char arch_dir[64] = {};
    // The directory of the image, the archive, or the program that carries it.
    char directory[1024] = {};
    // Why the last image asked for was not given, when it was found and refused.
    char refusal[256] = {};
    okld_host host{};
};

bool join(char* out, unsigned long cap, const char* a, const char* b, const char* c = nullptr) {
    unsigned long at = 0;
    auto put = [&](const char* s) { for (; s && *s; ++s) { if (at + 1 >= cap) return false; out[at++] = *s; } return true; };
    if (!put(a)) return false;
    const char* const parts[] = { b, c };
    for (const char* part : parts) {
        if (!part || !*part) continue;
        if (at && !separator(out[at - 1]) && !put("/")) return false;
        if (!put(part)) return false;
    }
    out[at] = 0;
    return true;
}

// A member of the archive by name, admitted (stored, aligned, its stated content).
const void* archive_member(search& s, const char* member, unsigned long long& size) {
    okld_zip_member m{};
    okld_why why{};
    if (okld_zip_find(s.archive, s.archive_size, member, &m, &why) != 0) return nullptr;
    if (okld_okb_admit(s.archive, s.archive_size, &m, s.json, s.json_size, &why) != 0) {
        copy_text(s.refusal, sizeof s.refusal, why.text);
        return nullptr;
    }
    size = m.size;
    return s.archive + m.data;
}

const void* archive_image(search& s, const char* name, unsigned long long& size) {
    char member[512];
    if (s.arch_dir[0] && join(member, sizeof member, s.arch_dir, name))
        if (const void* p = archive_member(s, member, size)) return p;
    if (s.refusal[0]) return nullptr;
    return archive_member(s, name, size);
}

// The separator of OKRUN_PATH: the system's own, as its PATH is written.
char list_separator() {
    char system[16];
    const kal_intptr n = kal_env_system(system, sizeof system);
    return (n == 7 && same_bytes(system, "windows", 7)) ? ';' : ':';
}

bool read_candidate(search& s, const char* path, file_bytes& f) {
    char why[8];
    return read_all(path, f, why, sizeof why);
}

// The file search: beside, then `lib/<arch>/' and `lib/' there, then OKRUN_PATH.
bool find_file(search& s, const char* name, file_bytes& f, char* found = nullptr, unsigned long found_cap = 0) {
    char path[2048];
    auto attempt = [&](const char* a, const char* b, const char* c) {
        if (!join(path, sizeof path, a, b, c)) return false;
        if (!read_candidate(s, path, f)) return false;
        if (found) copy_text(found, found_cap, path);
        return true;
    };
    char lib_arch[64];
    join(lib_arch, sizeof lib_arch, "lib", okrun_arch);
    if (s.directory[0] && (attempt(s.directory, name, nullptr) || attempt(s.directory, lib_arch, name)
                           || attempt(s.directory, "lib", name)))
        return true;
    char list[4096];
    const kal_intptr n = kal_env_var("OKRUN_PATH", 10, list, sizeof list - 1);
    if (n <= 0 || n >= static_cast<kal_intptr>(sizeof list)) return false;
    list[n] = 0;
    const char sep = list_separator();
    for (char* at = list; *at;) {
        char* end = at;
        while (*end && *end != sep) ++end;
        const char was = *end;
        *end = 0;
        if (*at && (attempt(at, okrun_arch, name) || attempt(at, name, nullptr))) return true;
        if (!was) break;
        at = end + 1;
    }
    return false;
}

// An image another needs (DT_NEEDED), by the search above. The bytes are the
// archive's own, or the group's, or a file's read here; the loader keeps no
// pointer into them (it places each segment), so a file's are released when
// the loader gives them back.
const void* find_needed(const char* name, okld_size* size, void* ctx) {
    auto& s = *static_cast<search*>(ctx);
    s.refusal[0] = 0;
    const void* bytes = nullptr;
    unsigned long long n = 0;
    for (unsigned long i = 0; !bytes && i < s.image_count; ++i)
        if (same(s.images[i].name, name)) { bytes = s.images[i].bytes; n = s.images[i].size; }
    if (!bytes && s.archive) {
        bytes = archive_image(s, name, n);
        if (!bytes && s.refusal[0]) return nullptr;
    }
    file_bytes f;
    if (!bytes && find_file(s, name, f)) { bytes = f.data; n = f.size; }
    if (!bytes) return nullptr;
    char why[256];
    if (!admit(bytes, n, name, s.options, why, sizeof why)) {
        copy_text(s.refusal, sizeof s.refusal, why);
        if (f.data) release_file(f);
        return nullptr;
    }
    *size = n;
    return bytes;
}

void release_needed(const void* bytes, okld_size, void* ctx) {
    // A file read by `find_needed' was allocated with its capacity, which is
    // not known here; the loader's record does not point into the bytes, so
    // they are kept rather than released with a wrong size. A module needed by
    // several is read once.
    (void)bytes; (void)ctx;
}

void prepare_host(search& s) {
    okld_host& host = s.host;
    host.reserve = &reserve; host.publish = &publish; host.release = &release;
    host.granularity = &granularity; host.resolve = &resolve;
    host.alloc = &allocate; host.free = &deallocate;
    host.find_needed = &find_needed; host.release_bytes = &release_needed;
    host.debugger = s.options ? s.options->debugger : 0;
    host.ctx = &s;
}

using image_function = void (OKRUN_IMAGE_ABI*)(void);
using image_main = int (OKRUN_IMAGE_ABI*)(void);
void call_image(void* fn, void*) { reinterpret_cast<image_function>(fn)(); }

// Loads an admitted image with the search, and enters it. Returns only when
// it could not be started.
int enter(search& s, const void* bytes, unsigned long long size, const char* name,
          int argc, const char* const* argv, char* why, unsigned long long cap) {
    if (!admit(bytes, size, name, s.options, why, cap)) return -1;
    state().argc = argc;
    state().argv = argv;
    state().name = name;
    state().carried = s.options && s.options->carried;
    state().started = true;
    prepare_host(s);
    okld_module* m = nullptr;
    okld_why reason{};
    if (okld_load(bytes, size, name, &s.host, &m, &reason) != 0) {
        if (s.refusal[0]) text(why, cap) << name << ": " << s.refusal;
        else text(why, cap) << name << ": " << reason.text;
        return -1;
    }
    void* entry = okld_entry(m);
    if (!entry) { text(why, cap) << name << ": the image has no entry"; return -1; }
    okld_initialise(m, &call_image, nullptr);
    const int status = reinterpret_cast<image_main>(entry)();
    okld_finalise(m, &call_image, nullptr);
    kal_exit(status);
}

// The directory a carried image's needs are found beside: the program's.
void program_directory(char* out, unsigned long cap) {
    char self[1024];
    const kal_intptr n = kal_env_image(self, sizeof self - 1);
    if (n <= 0 || n >= static_cast<kal_intptr>(sizeof self)) { copy_text(out, cap, "."); return; }
    self[n] = 0;
    directory_of(self, out, cap);
}

// An archive of images in memory: its manifest (when it has one), checked and,
// where asked, its signature; this architecture's directory; the entry.
int run_archive(search& s, const char* entry, const char* name, int argc, const char* const* argv,
                char* why, unsigned long long cap) {
    okld_why reason{};
    okld_zip_member json{};
    const int has_json = okld_zip_find(s.archive, s.archive_size, "okb.json", &json, &reason);
    if (has_json < 0) { text(why, cap) << name << ": " << reason.text; return -1; }
    okld_okb_manifest manifest{};
    if (has_json == 0) {
        if (okld_okb_admit(s.archive, s.archive_size, &json, nullptr, 0, &reason) != 0
            || okld_okb_read_manifest(s.archive + json.data, json.size, &manifest, &reason) != 0) {
            text(why, cap) << name << ": " << reason.text;
            return -1;
        }
        s.json = s.archive + json.data;
        s.json_size = json.size;
        // THE MANIFEST'S SIGNATURE covers every member's digest, so with each
        // image's own it is what `require_signature' asks of the whole okb.
        if (signature_required(s.options)) {
            okld_zip_member sig{};
            if (okld_zip_find(s.archive, s.archive_size, "okb.sig", &sig, &reason) != 0 || sig.size != 96
                || okld_okb_admit(s.archive, s.archive_size, &sig, nullptr, 0, &reason) != 0) {
                text(why, cap) << name << ": its okb.json is not signed (okb.sig), and a signature is required";
                return -1;
            }
            const unsigned char* k = s.archive + sig.data;
            if (okld_verify_message(k, s.json, s.json_size, k + 32) != 1) { text(why, cap) << name << ": the signature of its okb.json does not hold"; return -1; }
            if (!key_is_trusted(s.options, k)) { text(why, cap) << name << ": its okb.json is signed by a key that is not trusted"; return -1; }
        }
        const okld_okb_arch* mine = nullptr;
        for (okld_u32 i = 0; i < manifest.arch_count; ++i)
            if (same(manifest.archs[i].name, okrun_arch)) mine = &manifest.archs[i];
        if (!mine) {
            text t(why, cap);
            t << name << " holds no image for " << okrun_arch << " (it holds";
            for (okld_u32 i = 0; i < manifest.arch_count; ++i) t << " " << manifest.archs[i].name;
            t << ")";
            return -1;
        }
        copy_text(s.arch_dir, sizeof s.arch_dir, mine->dir);
        if (!entry) entry = mine->entry;
    } else {
        copy_text(s.arch_dir, sizeof s.arch_dir, okrun_arch);
    }
    if (!entry || !*entry) { text(why, cap) << name << ": no entry is named, and it has no okb.json that names one"; return -1; }
    unsigned long long size = 0;
    s.refusal[0] = 0;
    const void* bytes = archive_image(s, entry, size);
    if (!bytes) {
        // A refusal names the member; the archive is named before it when it
        // has a name of its own (a file).
        text t(why, cap);
        if (!same(name, entry)) t << name << ": ";
        if (s.refusal[0]) t << s.refusal;
        else t << "no member " << entry << " (in " << s.arch_dir << "/ or at the root)";
        return -1;
    }
    const bool carried = s.options && s.options->carried;
    return enter(s, bytes, size, carried ? entry : name, argc, argv, why, cap);
}

// The search's state outlives the image: it is static for a run, which never
// returns, and allocated for a library, which is closed.
search g_search;

}  // namespace

image_state& state() { return g_state; }

}  // namespace okrun

using namespace okrun;

extern "C" const char* const* okrun_names(unsigned long* count) {
    static const char* names[256];
    static unsigned long n = 0;
    if (n == 0) {
        unsigned long k = 0;
        const binding* t = bindings(k);
        for (unsigned long i = 0; i < k && n < 256; ++i) names[n++] = t[i].name;
        t = space_bindings(k);
        for (unsigned long i = 0; t && i < k && n < 256; ++i) names[n++] = t[i].name;
    }
    if (count) *count = n;
    return names;
}

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
    search& s = g_search;
    s.options = options;
    if (options && options->carried) program_directory(s.directory, sizeof s.directory);
    else directory_of(name, s.directory, sizeof s.directory);
    if (is_archive(bytes, size)) {
        s.archive = static_cast<const unsigned char*>(bytes);
        s.archive_size = size;
        return run_archive(s, nullptr, name, argc, argv, why, cap);
    }
    return enter(s, bytes, size, name, argc, argv, why, cap);
}

extern "C" int okrun_run_file(const char* path, int argc, const char* const* argv,
                              const okrun_options* options, char* why, unsigned long long cap) {
    file_bytes f;
    if (!read_all(path, f, why, cap)) return -1;
    return okrun_run_bytes(f.data, f.size, path, argc, argv, options, why, cap);
}

extern "C" int okrun_run_okb_bytes(const void* bytes, unsigned long long size, const char* entry,
                                   int argc, const char* const* argv, const okrun_options* options,
                                   char* why, unsigned long long cap) {
    search& s = g_search;
    s.options = options;
    if (!is_archive(bytes, size)) { text(why, cap) << "the bytes are not an archive of images (docs/okb.md)"; return -1; }
    s.archive = static_cast<const unsigned char*>(bytes);
    s.archive_size = size;
    if (options && options->carried) program_directory(s.directory, sizeof s.directory);
    else if (argc > 0 && argv && argv[0]) directory_of(argv[0], s.directory, sizeof s.directory);
    else copy_text(s.directory, sizeof s.directory, ".");
    return run_archive(s, entry, entry ? entry : "the archive", argc, argv, why, cap);
}

extern "C" int okrun_run_images(const okrun_image* images, unsigned long count, const char* entry,
                                int argc, const char* const* argv, const okrun_options* options,
                                char* why, unsigned long long cap) {
    search& s = g_search;
    s.options = options;
    s.images = images;
    s.image_count = count;
    if (options && options->carried) program_directory(s.directory, sizeof s.directory);
    else if (argc > 0 && argv && argv[0]) directory_of(argv[0], s.directory, sizeof s.directory);
    else copy_text(s.directory, sizeof s.directory, ".");
    for (unsigned long i = 0; i < count; ++i)
        if (entry && same(images[i].name, entry))
            return enter(s, images[i].bytes, images[i].size, images[i].name, argc, argv, why, cap);
    text(why, cap) << "the group of images has no " << (entry ? entry : "entry");
    return -1;
}

// --- libraries ------------------------------------------------------------------

struct okrun_library {
    okld_module*  module = nullptr;
    search        s;
    unsigned char* bytes = nullptr;   // a file's, mapped or read here
    unsigned long long size = 0, cap = 0;
};

namespace {

okrun_library* open_loaded(okrun_library* lib, const void* bytes, unsigned long long size, const char* name,
                           char* why, unsigned long long cap) {
    if (!admit(bytes, size, name, lib->s.options, why, cap)) return nullptr;
    prepare_host(lib->s);
    okld_why reason{};
    if (okld_load(bytes, size, name, &lib->s.host, &lib->module, &reason) != 0) {
        if (lib->s.refusal[0]) text(why, cap) << name << ": " << lib->s.refusal;
        else text(why, cap) << name << ": " << reason.text;
        return nullptr;
    }
    okld_initialise(lib->module, &call_image, nullptr);
    return lib;
}

okrun_library* new_library(const okrun_options* options) {
    auto* lib = static_cast<okrun_library*>(kal_alloc(sizeof(okrun_library), 16));
    if (!lib) return nullptr;
    auto* b = reinterpret_cast<unsigned char*>(lib);
    for (unsigned long i = 0; i < sizeof(okrun_library); ++i) b[i] = 0;
    lib->s.options = options;
    return lib;
}

void free_library(okrun_library* lib) {
    if (!lib) return;
    release_bytes(lib->bytes, lib->size, lib->cap);
    kal_free(lib, sizeof(okrun_library), 16);
}

bool has_separator(const char* s) { for (; *s; ++s) if (separator(*s)) return true; return false; }

}  // namespace

extern "C" okrun_library* okrun_open_library(const char* path, const okrun_options* options,
                                             char* why, unsigned long long cap) {
    okrun_library* lib = new_library(options);
    if (!lib) { text(why, cap) << "no memory for a library"; return nullptr; }
    file_bytes f;
    char found[2048];
    if (has_separator(path)) {
        if (!read_all(path, f, why, cap)) { free_library(lib); return nullptr; }
        copy_text(found, sizeof found, path);
    } else {
        // A bare name is the program's: beside it, then `lib/<arch>/', `lib/',
        // OKRUN_PATH.
        program_directory(lib->s.directory, sizeof lib->s.directory);
        if (!find_file(lib->s, path, f, found, sizeof found)) {
            text(why, cap) << path << " is not beside the program (" << lib->s.directory << "), in its lib/" << okrun_arch
                           << "/ or lib/, or in OKRUN_PATH";
            free_library(lib);
            return nullptr;
        }
    }
    directory_of(found, lib->s.directory, sizeof lib->s.directory);
    lib->bytes = f.data;
    lib->size = f.size;
    lib->cap = f.cap;
    if (!open_loaded(lib, f.data, f.size, found, why, cap)) { free_library(lib); return nullptr; }
    return lib;
}

extern "C" okrun_library* okrun_open_library_bytes(const void* bytes, unsigned long long size, const char* name,
                                                   const okrun_options* options, char* why, unsigned long long cap) {
    okrun_library* lib = new_library(options);
    if (!lib) { text(why, cap) << "no memory for a library"; return nullptr; }
    program_directory(lib->s.directory, sizeof lib->s.directory);
    if (!open_loaded(lib, bytes, size, name, why, cap)) { free_library(lib); return nullptr; }
    return lib;
}

extern "C" void* okrun_symbol(okrun_library* lib, const char* name) {
    return lib && lib->module ? okld_symbol(lib->module, name) : nullptr;
}

extern "C" void okrun_close(okrun_library* lib) {
    if (!lib) return;
    if (lib->module) {
        okld_finalise(lib->module, &call_image, nullptr);
        okld_unload(lib->module);
    }
    free_library(lib);
}
