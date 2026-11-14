// THE CORE RUNNER (0.6.3): an image, or an archive of images, that the program carries runs from
// memory where the implementation provides no file system, processes or contexts --- firmware,
// a single-task system (mcpp.toml, `cfg(interface = ...)`). Its code is placed through openkal.exec, the names
// it imports are bound as the full runner binds them (bindings.cpp), and the images it needs are
// the archive's. It keeps no cache and makes no snapshot: there is nowhere to keep one. The C
// interface is the full runner's; what needs a file answers that this runner reads none.
#include <okrun.h>
#include <okld.h>
#include <openkal.h>

#include "../image_abi.h"
#include "../runner.h"


namespace okrun {

namespace {

image_state g_state;

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

// --- the host the loader asks ------------------------------------------------------------------
void* reserve(okld_size n, void*) { return kal_exec_alloc(n); }
void* reserve_at(void* at, okld_size n, void*) { return kal_exec_alloc_at(at, n); }
int publish(void* region, okld_size off, okld_size n, void*) { return kal_exec_publish_part(region, off, n); }
int seal(void* region, okld_size off, okld_size n, int forever, void*) {
    return kal_exec_seal_part(region, off, n, forever ? KAL_EXEC_SEAL_FOREVER : 0);
}
void release(void* region, okld_size n, void*) { kal_exec_free(region, n); }
okld_size granularity(void*) { return kal_exec_granularity(); }
void* resolve(const char* name, void*) { return okrun_resolve(name); }
void* allocate(okld_size n, void*) { return kal_alloc(n, 16); }
void deallocate(void* p, okld_size n, void*) { kal_free(p, n, 16); }

// --- the images a run holds: a group in memory, or an archive's members ------------------------
struct search {
    const okrun_options* options = nullptr;
    const okrun_image* images = nullptr;
    unsigned long image_count = 0;
    const unsigned char* archive = nullptr;
    unsigned long long archive_size = 0;
    const void* json = nullptr;
    unsigned long long json_size = 0;
    char arch_dir[64] = {};
    char refusal[256] = {};
    okld_host host{};
};
search g_search;

// A member of the archive: stored, its bytes in place; compressed, expanded into memory the run
// keeps (the loader keeps no pointer into the bytes, but the run never returns to free them).
const void* archive_member(search& s, const char* member, unsigned long long& size) {
    okld_zip_member m{};
    okld_why why{};
    if (okld_zip_find(s.archive, s.archive_size, member, &m, &why) != 0) return nullptr;
    if (m.method == 8) {
        void* out = kal_alloc(m.original ? m.original : 1, 16);
        if (!out) { copy_text(s.refusal, sizeof s.refusal, "no memory to expand a compressed member"); return nullptr; }
        if (okld_okb_expand(s.archive, s.archive_size, &m, s.json, s.json_size, out, m.original, &why) != 0) {
            copy_text(s.refusal, sizeof s.refusal, why.text[0] ? why.text : "a compressed member could not be expanded");
            kal_free(out, m.original ? m.original : 1, 16);
            return nullptr;
        }
        size = m.original;
        return out;
    }
    if (okld_okb_admit(s.archive, s.archive_size, &m, s.json, s.json_size, &why) != 0) {
        copy_text(s.refusal, sizeof s.refusal, why.text);
        return nullptr;
    }
    size = m.size;
    return s.archive + m.data;
}

bool join(char* out, unsigned long cap, const char* a, const char* b) {
    text t(out, cap);
    t << a << "/" << b;
    return t.at + 1 < cap;
}

const void* archive_image(search& s, const char* name, unsigned long long& size) {
    char member[512];
    if (s.arch_dir[0] && join(member, sizeof member, s.arch_dir, name))
        if (const void* p = archive_member(s, member, size)) return p;
    if (s.refusal[0]) return nullptr;
    return archive_member(s, name, size);
}

const void* find_needed(const char* name, okld_size* size, void* ctx) {
    auto& s = *static_cast<search*>(ctx);
    for (unsigned long i = 0; i < s.image_count; ++i)
        if (same(s.images[i].name, name)) { *size = s.images[i].size; return s.images[i].bytes; }
    if (s.archive) {
        unsigned long long n = 0;
        if (const void* p = archive_image(s, name, n)) { *size = n; return p; }
    }
    return nullptr;
}
void release_needed(const void*, okld_size, void*) {}

const char* interface_name(int bit) {
    static const char* const names[] = { "openkal.abort", "openkal.stream", "openkal.memory", "openkal.env",
        "openkal.time", "openkal.random", "openkal.fs", "openkal.process", "openkal.task", "openkal.exec",
        "openkal.terminal", "openkal.net", "openkal.datagram", "openkal.space", "openkal.timeout",
        "openkal.map", "openkal.region", "openkal.prof", "openkal.debug" };
    return bit >= 0 && bit < static_cast<int>(sizeof names / sizeof *names) ? names[bit] : "an interface";
}

bool key_is_trusted(const okrun_options* options, const unsigned char key[32]) {
    if (!options || !options->trusted_count) return true;
    for (unsigned i = 0; i < options->trusted_count; ++i) {
        bool same_key = true;
        for (int k = 0; k < 32; ++k) if (options->trusted[i * 32 + k] != key[k]) { same_key = false; break; }
        if (same_key) return true;
    }
    return false;
}

// What every image is asked before it is loaded, as the full runner asks it.
bool admit(const void* bytes, unsigned long long size, const char* name, const okrun_options* options,
           char* why, unsigned long long cap) {
    okld_info info{};
    okld_why reason{};
    if (okld_read(bytes, size, &info, &reason) != 0) { text(why, cap) << name << ": " << reason.text; return false; }
    if (!info.has_requirements) { text(why, cap) << name << ": no requirements note (SPEC 12.4); not an image"; return false; }
    if (info.format_major > OKLD_FORMAT_MAJOR) { text(why, cap) << name << ": written to a later version of the format than this runner reads"; return false; }
    if (const char* arch = okld_okb_arch_of(info.machine); !arch || !same(arch, okrun_arch)) {
        text(why, cap) << name << ": an image of " << (arch ? arch : "another architecture") << ", and this machine is " << okrun_arch;
        return false;
    }
    if (const unsigned long long missing = info.interfaces & ~own_interfaces()) {
        text t(why, cap);
        t << name << " requires";
        for (int bit = 0; bit < 64; ++bit) if (missing & (1ull << bit)) t << " " << interface_name(bit);
        t << ", which this system's openkal does not provide";
        return false;
    }
    if (options && (options->require_signature || options->trusted_count)) {
        unsigned char key[32] = {};
        const int v = okld_verify(bytes, size, key);
        if (v < 0) { text(why, cap) << name << ": its signature does not hold"; return false; }
        if (v == 0) { text(why, cap) << name << ": it is not signed, and a signature is required"; return false; }
        if (!key_is_trusted(options, key)) { text(why, cap) << name << ": it is signed by a key that is not trusted"; return false; }
    }
    return true;
}

using image_function = void (OKRUN_IMAGE_ABI*)(void);
using image_main = int (OKRUN_IMAGE_ABI*)(void);
void call_image(void* fn, void*) {
    const unsigned long long fp = okrun_fp_enter();
    reinterpret_cast<image_function>(fn)();
    okrun_fp_leave(fp);
}

// Loads an admitted image with the images it needs, and enters it. Returns only when it could not
// be started.
int enter(search& s, const void* bytes, unsigned long long size, const char* name,
          int argc, const char* const* argv, char* why, unsigned long long cap) {
    if (!admit(bytes, size, name, s.options, why, cap)) return -1;
    g_state.argc = argc;
    g_state.argv = argv;
    g_state.name = name;
    g_state.carried = s.options && s.options->carried;
    g_state.started = true;
    okld_host& h = s.host;
    h.reserve = &reserve; h.publish = &publish; h.release = &release; h.map = nullptr;
    h.granularity = &granularity; h.resolve = &resolve;
    h.alloc = &allocate; h.free = &deallocate;
    h.find_needed = &find_needed; h.release_bytes = &release_needed;
    h.reserve_at = (kal_exec_props() & KAL_EXEC_PROP_PLACE) ? &reserve_at : nullptr;
    h.seal = &seal;
    h.debugger = s.options ? s.options->debugger : 0;
    h.permanent = 1;
    h.prefetch = 0;
    h.ctx = &s;
    okld_module* m = nullptr;
    okld_why reason{};
    if (okld_load(bytes, size, name, &h, &m, &reason) != 0) {
        text t(why, cap);
        t << name << ": " << (s.refusal[0] ? s.refusal : reason.text);
        return -1;
    }
    void* entry = okld_entry(m);
    if (!entry) { text(why, cap) << name << ": the image has no entry"; return -1; }
    okrun_fp_enter();
    okld_initialise(m, &call_image, nullptr);
    const int status = reinterpret_cast<image_main>(entry)();
    okld_finalise(m, &call_image, nullptr);
    kal_exit(status);
}

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
        const okld_okb_arch* mine = nullptr;
        for (okld_u32 i = 0; i < manifest.arch_count; ++i)
            if (same(manifest.archs[i].name, okrun_arch)) mine = &manifest.archs[i];
        if (!mine) { text(why, cap) << name << " holds no image for " << okrun_arch; return -1; }
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
        text t(why, cap);
        t << name << ": " << (s.refusal[0] ? s.refusal : "no such member: ") << (s.refusal[0] ? "" : entry);
        return -1;
    }
    return enter(s, bytes, size, s.options && s.options->carried ? entry : name, argc, argv, why, cap);
}

bool is_archive(const void* bytes, unsigned long long size) {
    const auto* b = static_cast<const unsigned char*>(bytes);
    return size >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4;
}

}  // namespace

image_state& state() { return g_state; }

}  // namespace okrun

using namespace okrun;

extern "C" int okrun_run_bytes(const void* bytes, unsigned long long size, const char* name,
                               int argc, const char* const* argv, const okrun_options* options,
                               char* why, unsigned long long cap) {
    search& s = g_search;
    s.options = options;
    if (is_archive(bytes, size)) {
        s.archive = static_cast<const unsigned char*>(bytes);
        s.archive_size = size;
        return run_archive(s, nullptr, name, argc, argv, why, cap);
    }
    return enter(s, bytes, size, name, argc, argv, why, cap);
}

extern "C" int okrun_run_file(const char* path, int, const char* const*, const okrun_options*,
                              char* why, unsigned long long cap) {
    text(why, cap) << path << ": this runner reads no file (the implementation provides no openkal.fs); "
                   << "a program carries its image";
    return -1;
}

extern "C" int okrun_run_okb_bytes(const void* bytes, unsigned long long size, const char* entry,
                                   int argc, const char* const* argv, const okrun_options* options,
                                   char* why, unsigned long long cap) {
    search& s = g_search;
    s.options = options;
    if (!is_archive(bytes, size)) { text(why, cap) << "the bytes are not an archive of images (docs/okb.md)"; return -1; }
    s.archive = static_cast<const unsigned char*>(bytes);
    s.archive_size = size;
    return run_archive(s, entry, entry ? entry : "the archive", argc, argv, why, cap);
}

extern "C" int okrun_run_images(const okrun_image* images, unsigned long count, const char* entry,
                                int argc, const char* const* argv, const okrun_options* options,
                                char* why, unsigned long long cap) {
    search& s = g_search;
    s.options = options;
    s.images = images;
    s.image_count = count;
    for (unsigned long i = 0; i < count; ++i)
        if (entry && same(images[i].name, entry))
            return enter(s, images[i].bytes, images[i].size, images[i].name, argc, argv, why, cap);
    text(why, cap) << "the group of images has no " << (entry ? entry : "entry");
    return -1;
}

// A library of this system's program is a full runner's: the core runner has no file to open one
// from and no second program to place one beside.
extern "C" okrun_library* okrun_open_library(const char* path, const okrun_options*, char* why,
                                             unsigned long long cap) {
    text(why, cap) << (path ? path : "a library") << ": this runner opens no library";
    return nullptr;
}
extern "C" okrun_library* okrun_open_library_bytes(const void*, unsigned long long, const char* name,
                                                   const okrun_options*, char* why, unsigned long long cap) {
    text(why, cap) << (name ? name : "a library") << ": this runner opens no library";
    return nullptr;
}
extern "C" void* okrun_symbol(okrun_library*, const char*) { return nullptr; }
extern "C" void okrun_close(okrun_library*) {}

// The core runner keeps nothing for this machine.
extern "C" unsigned long long okrun_cache_list(void (*)(const char*, unsigned long long, int, void*), void*) {
    return 0;
}
extern "C" unsigned long long okrun_cache_reclaim(int) { return 0; }

