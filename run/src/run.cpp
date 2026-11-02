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
// At the base an image states (openkal 0.23, SPEC 12.3), where the
// implementation places memory where it is asked. OKRUN_PLACE=0 places every
// image anywhere and relocates it, as one that states no base is.
void* reserve_at(void* at, okld_size n, void*) { return kal_exec_alloc_at(at, n); }
bool placing() {
    if (!(kal_exec_props() & KAL_EXEC_PROP_PLACE)) return false;
    char v[4];
    const kal_intptr n = kal_env_var("OKRUN_PLACE", 11, v, sizeof v);
    return !(n == 1 && v[0] == '0');
}
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
// into where the file cannot be mapped. `cap' is zero for a region. A region's
// file stays open while its bytes are held, so that the loader can make part of
// an image the file's own pages (okld_host::map, 0.3).
struct file_bytes {
    unsigned char* data = nullptr;
    unsigned long long size = 0, cap = 0;
    kal_file file{};
    bool open = false;
};

void release_bytes(unsigned char* data, unsigned long long size, unsigned long long cap) {
    if (!data) return;
    if (cap == 0) kal_map_release(data, static_cast<kal_uintptr>(size));
    else kal_free(data, cap, 16);
}

void release_file(file_bytes& f) {
    release_bytes(f.data, f.size, f.cap);
    if (f.open) kal_fs_close_file(f.file);
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
    out.file = f;
    out.open = true;
    return true;
}

bool read_all(const char* path, file_bytes& out, char* why, unsigned long long cap) {
    kal_dir dir{};
    const char* rest = nullptr;
    if (!locate(path, dir, rest)) { text(why, cap) << path << " is beneath no directory this program was given"; return false; }
    unsigned long n = length(rest);
    kal_file f{};
    if (kal_fs_open(dir, rest, n, KAL_OPEN_READ, &f) != kal_ok) { text(why, cap) << path << " cannot be opened"; return false; }
    if (map_all(f, out)) return true;
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
        "openkal.map", "openkal.region", "openkal.prof", "openkal.debug",
    };
    return bit < static_cast<int>(sizeof names / sizeof names[0]) ? names[bit]
                                                                  : "an interface this runner does not know";
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
    // The loader's own interfaces are provided whatever the implementation
    // provides (SPEC 12.3, 0.2).
    unsigned long long provided = kal_interfaces() | KAL_IFACE_PROF | KAL_IFACE_DEBUG;
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
    // THE FILES THIS SEARCH HOLDS, released once the loader is done with them
    // (it keeps no pointer into an image's bytes): the file run, and each file
    // read for an image another needs until the loader gives it back.
    file_bytes ran{};
    file_bytes needed[16] = {};
    // The prepared copy of the entry image for this boot's base (0.4), held
    // while the loader maps its blocks.
    file_bytes prepared{};
    // The member of the archive last admitted: the entry, when it is run (its
    // digest is the manifest's).
    char member[512] = {};
    // Where each was read from, for a measurement and openkal.debug (0.2):
    // the file run (empty for bytes a program carries), and each needed file's
    // path and the name it was needed by.
    char ran_path[1024] = {};
    char needed_path[16][1024] = {};
    char needed_name[16][256] = {};
};

// The file a run's image or okb was read from, given back once the image is
// loaded: its pages are no longer resident beside the image's own.
void release_ran(search& s) {
    if (s.prepared.data) release_file(s.prepared);
    if (!s.ran.data) return;
    if (s.archive == s.ran.data) { s.archive = nullptr; s.archive_size = 0; s.json = nullptr; s.json_size = 0; }
    release_file(s.ran);
}

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

// THE CHUNKS OF A MEMBER ARE DIGESTED ON SEVERAL CONTEXTS AT ONCE (okb.json's
// `chunks', 0.1.8): libokld has no contexts of its own and asks for these. The
// calling context runs the first job; one that cannot be started runs here too.
struct chunk_task { void (*job)(okld_u64, void*); okld_u64 index; void* ctx; };
void run_chunk_task(void* p) {
    auto* t = static_cast<chunk_task*>(p);
    t->job(t->index, t->ctx);
}
void in_parallel(void (*job)(okld_u64, void*), okld_u64 count, void* ctx, void*) {
    constexpr okld_u64 kMost = 16;
    chunk_task tasks[kMost];
    kal_task started[kMost];
    bool running[kMost] = {};
    for (okld_u64 i = 1; i < count && i < kMost; ++i) {
        tasks[i] = { job, i, ctx };
        running[i] = kal_task_start(&run_chunk_task, &tasks[i], &started[i]) == kal_ok;
        if (!running[i]) job(i, ctx);
    }
    for (okld_u64 i = kMost; i < count; ++i) job(i, ctx);
    if (count) job(0, ctx);
    for (okld_u64 i = 1; i < count && i < kMost; ++i)
        if (running[i]) kal_task_join(started[i]);
}

// --- an okb's admission, remembered (0.2) ------------------------------------
//
// EVERY START OF AN OKB READ EVERY BYTE OF THE IMAGES IT RAN, to compare them
// with the digests okb.json states: 0.04 to 0.14 s for a 146 MB okb on CI's
// machines, and a language server that starts a worker per module it builds
// started 176 of them. The comparison is remembered per user, per okb.json (its
// SHA-256) and per member, with the identity, the length and the modification
// time of the file it was made on: a start of the same file finds the record and
// admits the member by its shape (stored, aligned) without reading it; a file
// replaced or changed in place has another identity or time, and is compared
// again. The record is in the user's own cache directory, which only the user
// can write --- a party that could write a record could as well write the okb
// it describes.
struct memo_place { kal_dir dir{}; bool usable = false; char key[65] = {}; char stamp[96] = {}; };

const char hex_digits[] = "0123456789abcdef";
void to_hex(const unsigned char* b, int n, char* out) {
    for (int i = 0; i < n; ++i) { out[2 * i] = hex_digits[b[i] >> 4]; out[2 * i + 1] = hex_digits[b[i] & 15]; }
    out[2 * n] = 0;
}
char* put_number(char* o, unsigned long long v) {
    char d[24]; int n = 0;
    do { d[n++] = static_cast<char>('0' + v % 10); v /= 10; } while (v);
    while (n) *o++ = d[--n];
    return o;
}

// A directory of components beneath a supplied one, each made in turn and one
// that exists entered: `rest' (a path's remainder beneath `root') and then each
// of `below'.
bool enter_path(kal_dir root, const char* rest, const char* const* below, unsigned below_count, kal_dir& out,
                bool* owned = nullptr) {
    kal_dir d = root;
    char part[1100]; unsigned long p = 0;
    auto enter_part = [&]() -> bool {
        if (p == 0) return true;
        kal_dir next{};
        kal_fs_mkdir(d, part, p);
        if (kal_fs_open_dir(d, part, p, &next) != kal_ok) return false;
        if (!(d.h == root.h)) kal_fs_close_dir(d);
        d = next;
        p = 0;
        return true;
    };
    for (const char* c = rest ? rest : ""; ; ++c) {
        if (*c == 0 || separator(*c)) { if (!enter_part()) return false; if (*c == 0) break; continue; }
        if (p + 1 < sizeof part) part[p++] = *c;
    }
    for (unsigned i = 0; i < below_count; ++i) {
        p = 0;
        for (const char* c = below[i]; *c && p + 1 < sizeof part; ++c) part[p++] = *c;
        if (!enter_part()) return false;
    }
    out = d;
    if (owned) *owned = !(d.h == root.h);
    return true;
}

// A directory named by a variable, entered (and made), then `below' in it.
bool directory_of_variable(const char* var, const char* const* below, unsigned below_count, kal_dir& out,
                           bool* owned = nullptr) {
    char path[1024];
    const kal_intptr n = kal_env_var(var, length(var), path, sizeof path - 1);
    if (n <= 0 || n >= static_cast<kal_intptr>(sizeof path)) return false;
    path[n] = 0;
    kal_dir root{};
    const char* rest = nullptr;
    return locate(path, root, rest) && enter_path(root, rest, below, below_count, out, owned);
}

// The user's cache directory, as this system places it, then `below'.
bool user_cache(const char* const* below, unsigned below_count, kal_dir& out, bool* owned = nullptr) {
    char system[16];
    const kal_intptr sn = kal_env_system(system, sizeof system);
    const bool windows = sn == 7 && same_bytes(system, "windows", 7);
    const bool macos = sn == 5 && same_bytes(system, "macos", 5);
    char base[1024]; kal_intptr n = -1;
    const char* tail = "";
    if (windows) { n = kal_env_var("LOCALAPPDATA", 12, base, sizeof base - 64); }
    else {
        n = macos ? -1 : kal_env_var("XDG_CACHE_HOME", 14, base, sizeof base - 64);
        if (n <= 0) { n = kal_env_var("HOME", 4, base, sizeof base - 64); tail = macos ? "/Library/Caches" : "/.cache"; }
    }
    if (n <= 0 || n >= static_cast<kal_intptr>(sizeof base - 64)) return false;
    base[n] = 0;
    char path[1200];
    if (!join(path, sizeof path, base, "")) return false;
    unsigned long at = length(path);
    if (at && separator(path[at - 1])) --at;
    for (const char* t = tail; *t && at + 1 < sizeof path; ++t) path[at++] = *t;
    path[at] = 0;
    kal_dir root{};
    const char* rest = nullptr;
    return locate(path, root, rest) && enter_path(root, rest, below, below_count, out, owned);
}

// `okrun/admitted' in the user's cache directory.
bool memo_directory(kal_dir& out) {
    static const char* const below[] = { "okrun", "admitted" };
    return user_cache(below, 2, out);
}

void memo_open(search& s, memo_place& m) {
    if (!s.ran_path[0] || !s.json) return;
    kal_dir dir{}; const char* rest = nullptr;
    if (!locate(s.ran_path, dir, rest)) return;
    kal_node_info info{};
    info.self_size = sizeof info;
    if (kal_fs_info(dir, rest, length(rest), 0, KAL_INFO_IDENTITY | KAL_INFO_SIZE | KAL_INFO_MODIFIED, &info) != kal_ok
        || !(info.present & KAL_INFO_IDENTITY) || !(info.present & KAL_INFO_MODIFIED))
        return;
    if (!memo_directory(m.dir)) return;
    unsigned char digest[32];
    okld_sha256(s.json, s.json_size, digest);
    to_hex(digest, 32, m.key);
    char* o = m.stamp;
    o = put_number(o, info.identity[0]); *o++ = ' ';
    o = put_number(o, info.identity[1]); *o++ = ' ';
    o = put_number(o, info.size); *o++ = ' ';
    o = put_number(o, info.modified_ns); *o++ = '\n'; *o = 0;
    m.usable = true;
}

// The record's name: the manifest's digest and the member's.
void memo_name(const memo_place& m, const char* member, char (&out)[160]) {
    unsigned char d[32];
    okld_sha256(member, length(member), d);
    char h[65];
    to_hex(d, 8, h);
    unsigned long at = 0;
    for (int i = 0; i < 64; ++i) out[at++] = m.key[i];
    out[at++] = '-';
    for (int i = 0; i < 16; ++i) out[at++] = h[i];
    out[at] = 0;
}

bool memo_holds(const memo_place& m, const char* member) {
    if (!m.usable) return false;
    char name[160];
    memo_name(m, member, name);
    kal_file f{};
    if (kal_fs_open(m.dir, name, length(name), KAL_OPEN_READ, &f) != kal_ok) return false;
    char have[96] = {};
    const kal_intptr n = kal_stream_read(kal_fs_stream(f), have, sizeof have - 1);
    kal_fs_close_file(f);
    const unsigned long want = length(m.stamp);
    return n == static_cast<kal_intptr>(want) && same_bytes(have, m.stamp, want);
}

void memo_record(const memo_place& m, const char* member) {
    if (!m.usable) return;
    char name[160];
    memo_name(m, member, name);
    kal_file f{};
    if (kal_fs_open(m.dir, name, length(name), KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f) != kal_ok) return;
    kal_stream_write(kal_fs_stream(f), m.stamp, length(m.stamp));
    kal_fs_close_file(f);
}

memo_place g_memo;
bool g_memo_opened = false;

// A member of the archive by name, admitted (stored, aligned, its stated content).
const void* archive_member(search& s, const char* member, unsigned long long& size) {
    okld_zip_member m{};
    okld_why why{};
    if (okld_zip_find(s.archive, s.archive_size, member, &m, &why) != 0) return nullptr;
    copy_text(s.member, sizeof s.member, member);
    if (!g_memo_opened) { g_memo_opened = true; memo_open(s, g_memo); }
    if (memo_holds(g_memo, member)) {
        // Compared before, on this file as it is: its shape alone is asked,
        // and no byte of it is read (0.3.1: the CRC-32 the archive states was
        // computed here, a pass over the whole member on every start).
        if (okld_okb_admit_layout(s.archive_size, &m, &why) != 0) {
            copy_text(s.refusal, sizeof s.refusal, why.text);
            return nullptr;
        }
    } else {
        if (okld_okb_admit_chunked(s.archive, s.archive_size, &m, s.json, s.json_size, &in_parallel, nullptr, &why) != 0) {
            copy_text(s.refusal, sizeof s.refusal, why.text);
            return nullptr;
        }
        memo_record(g_memo, member);
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
    char found[1024] = {};
    if (!bytes && find_file(s, name, f, found, sizeof found)) { bytes = f.data; n = f.size; }
    if (!bytes) return nullptr;
    char why[256];
    if (!admit(bytes, n, name, s.options, why, sizeof why)) {
        copy_text(s.refusal, sizeof s.refusal, why);
        if (f.data) release_file(f);
        return nullptr;
    }
    if (f.data) {
        // Held until the loader gives the bytes back (`release_needed').
        file_bytes* slot = nullptr;
        unsigned k = 0;
        for (auto& h : s.needed) { if (!h.data) { slot = &h; break; } ++k; }
        if (!slot) { release_file(f); copy_text(s.refusal, sizeof s.refusal, "more than sixteen files are needed at once"); return nullptr; }
        *slot = f;
        copy_text(s.needed_path[k], sizeof s.needed_path[k], found);
        copy_text(s.needed_name[k], sizeof s.needed_name[k], name);
    } else if (s.archive && bytes >= s.archive && bytes < s.archive + s.archive_size) {
        profile_loaded(name, bytes, n, s.ran_path[0] ? s.ran_path : nullptr,
                       static_cast<kal_u64>(static_cast<const unsigned char*>(bytes) - s.archive));
    } else {
        profile_loaded(name, bytes, n, nullptr, 0);
    }
    *size = n;
    return bytes;
}

// A file `find_needed' read is released with the size and capacity it was
// read with; the archive's and the group's bytes are not this search's.
void release_needed(const void* bytes, okld_size, void* ctx) {
    auto& s = *static_cast<search*>(ctx);
    for (unsigned k = 0; k < 16; ++k) {
        auto& h = s.needed[k];
        if (!h.data || h.data != bytes) continue;
        // The image is loaded by now: a measurement reads its symbols while its
        // bytes are at hand, and openkal.debug knows where to read them again.
        profile_loaded(s.needed_name[k], h.data, h.size, s.needed_path[k], 0);
        profile_settle();
        release_file(h);
        return;
    }
}

// Part of an image is the file's own pages where the bytes are a file this
// search holds (the file run, a library's, one read for an image another
// needs) at a multiple of the alignment, and the implementation reports
// KAL_EXEC_PROP_FILE (openkal 0.21). Bytes a program carries, a member of an
// archive and an implementation without the position are copied.
bool part_of(const file_bytes& f, const void* bytes, okld_size from, kal_u64& at) {
    const auto* b = static_cast<const unsigned char*>(bytes);
    if (!f.open || !f.data || b < f.data || b >= f.data + f.size) return false;
    at = static_cast<kal_u64>(b - f.data) + from;
    return at % KAL_MAP_ALIGNMENT == 0;
}

int map_part(void* region, okld_size offset, okld_size size, const void* bytes, okld_size from, int asked,
             void* ctx) {
    if (!(kal_exec_props() & KAL_EXEC_PROP_FILE)) return -1;
    auto& s = *static_cast<search*>(ctx);
    const kal_uintptr how = ((asked & OKLD_MAP_EXECUTE) ? KAL_EXEC_MAP_EXECUTE : 0)
                          | ((asked & OKLD_MAP_PREFETCH) ? KAL_EXEC_MAP_PREFETCH : 0)
                          | ((asked & OKLD_MAP_WRITE) ? KAL_EXEC_MAP_WRITE : 0);
    kal_u64 at = 0;
    if (part_of(s.ran, bytes, from, at))
        return kal_exec_map_part(region, offset, size, s.ran.file, at, how) == kal_ok ? 0 : -1;
    if (part_of(s.prepared, bytes, from, at))
        return kal_exec_map_part(region, offset, size, s.prepared.file, at, how) == kal_ok ? 0 : -1;
    for (const auto& f : s.needed)
        if (part_of(f, bytes, from, at))
            return kal_exec_map_part(region, offset, size, f.file, at, how) == kal_ok ? 0 : -1;
    return -1;
}

// Read-only after relocation (openkal 0.23), for good where the module is never
// unloaded.
int seal(void* region, okld_size offset, okld_size size, int forever, void*) {
    return kal_exec_seal_part(region, offset, size, forever ? KAL_EXEC_SEAL_FOREVER : 0) == kal_ok ? 0 : -1;
}

// WHETHER THE PAGES A START TOUCHES ARE READ IN AHEAD OF IT (0.4): memory spent
// for time, as the program's resource preference says (openkal 0.23) --- always
// for performance, never for economy, and where memory is plentiful (a quarter
// of it available) when balanced.
bool prefetching() {
    switch (kal_env_resources()) {
        case KAL_RESOURCES_PERFORMANCE: return true;
        case KAL_RESOURCES_ECONOMY:     return false;
        default: {
            kal_memory_status m{};
            m.self_size = sizeof m;
            if (kal_memory_info(&m) != kal_ok || !(m.present & KAL_MSTATUS_AVAILABLE) || !(m.present & KAL_MSTATUS_TOTAL))
                return false;
            return m.available_bytes >= m.total_bytes / 4;
        }
    }
}

// `permanent': the modules loaded are never unloaded (a run's entry image and
// those it needs), as against a library a program closes.
void prepare_host(search& s, bool permanent) {
    okld_host& host = s.host;
    host.reserve = &reserve; host.publish = &publish; host.release = &release; host.map = &map_part;
    host.granularity = &granularity; host.resolve = &resolve;
    host.alloc = &allocate; host.free = &deallocate;
    host.find_needed = &find_needed; host.release_bytes = &release_needed;
    host.reserve_at = placing() ? &reserve_at : nullptr;
    host.debugger = s.options ? s.options->debugger : 0;
    host.ctx = &s;
    host.seal = &seal;
    host.permanent = permanent ? 1 : 0;
    host.prefetch = prefetching() ? 1 : 0;
}


// --- this machine's base for an image (0.4) ------------------------------------------
//
// AN IMAGE AT THE BASE IT WAS SEALED WITH IS AT ONE ADDRESS ON EVERY MACHINE,
// which is what a program linked for one address is and what address space
// layout randomisation exists to undo. So a runner moves it: by a slide chosen
// at random once for each user and each boot, as this system's own shared
// libraries are moved, from the image's base of its digest. The first start of
// the boot computes the image's writable segments for that base --- the
// relocations of the sealed placement, applied for another base --- and writes
// them as a prepared copy (SPEC 12.4, type 5) beside the slide; every later
// start maps it. The copy is the user's, in a directory only the user writes;
// a party that could rewrite it could as well debug the user's programs.
//
//   OKRUN_PLACE=sealed   the base the image was sealed with
//   OKRUN_PLACE=0        anywhere, every relocation applied
//   OKRUN_CACHE=<dir>    the directory (else $XDG_RUNTIME_DIR/okrun, which this
//                        system empties at each boot, else the user's cache
//                        directory's okrun/placed)

enum class policy { local, sealed, anywhere };

policy placement_policy() {
    char v[16];
    const kal_intptr n = kal_env_var("OKRUN_PLACE", 11, v, sizeof v);
    if (n == 1 && v[0] == '0') return policy::anywhere;
    if (n == 6 && same_bytes(v, "sealed", 6)) return policy::sealed;
    return policy::local;
}

struct owned_dir {
    kal_dir d{};
    bool own = false;
    ~owned_dir() { if (own) kal_fs_close_dir(d); }
};

bool cache_directory(owned_dir& out) {
    static const char* const okrun_dir[] = { "okrun" };
    static const char* const placed[] = { "okrun", "placed" };
    return directory_of_variable("OKRUN_CACHE", nullptr, 0, out.d, &out.own)
        || directory_of_variable("XDG_RUNTIME_DIR", okrun_dir, 1, out.d, &out.own)
        || user_cache(placed, 2, out.d, &out.own);
}

// A small file of the directory, read whole.
kal_intptr read_small(kal_dir dir, const char* name, char* out, unsigned long cap) {
    kal_file f{};
    if (kal_fs_open(dir, name, length(name), KAL_OPEN_READ, &f) != kal_ok) return -1;
    const kal_intptr n = kal_stream_read(kal_fs_stream(f), out, cap - 1);
    kal_fs_close_file(f);
    if (n >= 0) out[n] = 0;
    return n;
}

// A file of the directory written whole, then put in place by one rename, so
// that a reader finds the old one or the new one and never a part.
bool write_whole(kal_dir dir, const char* name, const void* bytes, unsigned long long n) {
    char temp[256];
    {
        text t(temp, sizeof temp);
        unsigned char r[8] = {};
        kal_random_fill(r, sizeof r);
        char h[17];
        to_hex(r, 8, h);
        t << "." << name << "." << h << ".tmp";
    }
    kal_file f{};
    if (kal_fs_open(dir, temp, length(temp), KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f) != kal_ok)
        return false;
    const auto* b = static_cast<const unsigned char*>(bytes);
    unsigned long long done = 0;
    while (done < n) {
        const kal_intptr w = kal_stream_write(kal_fs_stream(f), b + done, n - done);
        if (w <= 0) break;
        done += static_cast<unsigned long long>(w);
    }
    kal_fs_close_file(f);
    if (done != n || kal_fs_rename(dir, temp, length(temp), dir, name, length(name)) != kal_ok) {
        kal_fs_remove(dir, temp, length(temp));
        return false;
    }
    return true;
}

unsigned long long parse_number(const char*& p) {
    unsigned long long v = 0;
    while (*p >= '0' && *p <= '9') v = v * 10 + static_cast<unsigned long long>(*p++ - '0');
    return v;
}

// THE SLIDE OF THIS BOOT: a multiple of 64 KiB below 16 TiB, kept with the wall
// time the boot began at (the wall clock less the monotonic one, which begins
// at the boot). Another boot has another beginning, and its first start chooses
// again and removes what was prepared for the last.
bool boot_slide(kal_dir dir, unsigned long long& slide) {
    const unsigned long long began = kal_time_wall() - kal_time_monotonic();
    char have[128];
    if (read_small(dir, "boot", have, sizeof have) > 0) {
        const char* p = have;
        const unsigned long long s0 = parse_number(p);
        if (*p == ' ') ++p;
        const unsigned long long b0 = parse_number(p);
        const unsigned long long apart = b0 > began ? b0 - began : began - b0;
        if (apart <= 2000000000ull && s0 % 65536 == 0 && s0 < (1ull << 44)) { slide = s0; return true; }
    }
    unsigned long long r = 0;
    if (kal_random_fill(&r, sizeof r) != kal_ok) return false;
    slide = (r % (1ull << 28)) << 16;
    // What was prepared for another boot is for another slide.
    kal_uintptr iter = 0;
    if (kal_fs_list_begin(dir, &iter) == kal_ok) {
        while (iter != 0) {
            char name[256]; kal_uintptr n = 0; int kind = 0;
            if (kal_fs_list_next(dir, &iter, name, sizeof name, &n, &kind) != kal_ok || iter == 0) break;
            if (n > 6 && n < sizeof name && same_bytes(name + n - 6, ".okseg", 6)) kal_fs_remove(dir, name, n);
            if (n > 7 && n < sizeof name && same_bytes(name + n - 7, ".oksnap", 7)) kal_fs_remove(dir, name, n);
        }
    }
    char line[96];
    char* o = put_number(line, slide);
    *o++ = ' ';
    o = put_number(o, began);
    *o++ = '\n';
    write_whole(dir, "boot", line, static_cast<unsigned long long>(o - line));
    return true;
}

// THE IMAGE'S DIGEST, its name in the cache: an okb member's is the one its
// manifest states, which its admission held it to; a file's is computed once
// and remembered by the file's identity, length and time, as an admission is.
bool image_digest(search& s, const void* bytes, unsigned long long size, unsigned char out[32]) {
    const auto* b = static_cast<const unsigned char*>(bytes);
    if (s.json && s.archive && b >= s.archive && b < s.archive + s.archive_size && s.member[0])
        return okld_okb_digest(s.json, s.json_size, s.member, out) == 1;
    if (!s.ran_path[0] || !s.ran.data || b < s.ran.data || b >= s.ran.data + s.ran.size) return false;
    kal_dir dir{};
    const char* rest = nullptr;
    if (!locate(s.ran_path, dir, rest)) return false;
    kal_node_info info{};
    info.self_size = sizeof info;
    if (kal_fs_info(dir, rest, length(rest), 0, KAL_INFO_IDENTITY | KAL_INFO_SIZE | KAL_INFO_MODIFIED, &info) != kal_ok
        || !(info.present & KAL_INFO_IDENTITY) || !(info.present & KAL_INFO_MODIFIED)) {
        okld_sha256(bytes, size, out);
        return true;
    }
    char stamp[128];
    char* o = stamp;
    o = put_number(o, info.identity[0]); *o++ = ' ';
    o = put_number(o, info.identity[1]); *o++ = ' ';
    o = put_number(o, info.size); *o++ = ' ';
    o = put_number(o, info.modified_ns); *o++ = ' ';
    *o = 0;
    const unsigned long stamp_len = static_cast<unsigned long>(o - stamp);
    static const char* const below[] = { "okrun", "digests" };
    owned_dir memo;
    char name[40];
    {
        unsigned char k[32];
        okld_sha256(s.ran_path, length(s.ran_path), k);
        to_hex(k, 16, name);
    }
    if (user_cache(below, 2, memo.d, &memo.own)) {
        char have[256];
        const kal_intptr n = read_small(memo.d, name, have, sizeof have);
        if (n == static_cast<kal_intptr>(stamp_len + 64) && same_bytes(have, stamp, stamp_len)) {
            for (int i = 0; i < 32; ++i) {
                auto nib = [](char c) { return c >= 'a' ? c - 'a' + 10 : c - '0'; };
                out[i] = static_cast<unsigned char>(nib(have[stamp_len + 2 * i]) * 16 + nib(have[stamp_len + 2 * i + 1]));
            }
            return true;
        }
    }
    okld_sha256(bytes, size, out);
    if (memo.d.h) {
        char line[256];
        unsigned long at = 0;
        for (unsigned long i = 0; i < stamp_len; ++i) line[at++] = stamp[i];
        to_hex(out, 32, line + at);
        write_whole(memo.d, name, line, at + 64);
    }
    return true;
}

// The prepared copy of the entry image for this boot's base, found or made,
// mapped into `s.prepared'. False leaves the image to its sealed base.
bool prepare_local(search& s, const void* bytes, unsigned long long size) {
    if (placement_policy() != policy::local || !s.host.reserve_at) return false;
    okld_u64 sealed = 0; okld_u32 count = 0;
    if (okld_placement(bytes, size, &sealed, &count) != 1 || count == 0) return false;
    unsigned char digest[32];
    if (!image_digest(s, bytes, size, digest)) return false;
    owned_dir dir;
    if (!cache_directory(dir)) return false;
    unsigned long long slide = 0;
    if (!boot_slide(dir.d, slide)) return false;
    // From the digest's own base, as okld_place_base chooses one, moved by the
    // slide within [16 TiB, 32 TiB - 4 GiB): room for a span of 4 GiB above.
    const unsigned long long slot = (static_cast<unsigned long long>(digest[0]) | static_cast<unsigned long long>(digest[1]) << 8) & 0xfff;
    const unsigned long long range = (1ull << 44) - (1ull << 32);
    const unsigned long long base = (1ull << 44) + (slot * (1ull << 32) + slide) % range;
    char name[96];
    {
        char h[33], b[17];
        to_hex(digest, 16, h);
        char* o = b;
        for (int sh = 60; sh >= 0; sh -= 4) *o++ = hex_digits[(base >> sh) & 15];
        *o = 0;
        text(name, sizeof name) << h << "-" << b << ".okseg";
    }
    auto found = [&]() -> bool {
        kal_file f{};
        if (kal_fs_open(dir.d, name, length(name), KAL_OPEN_READ, &f) != kal_ok) return false;
        file_bytes fb;
        if (!map_all(f, fb)) { kal_fs_close_file(f); return false; }
        okld_prepared_info info{};
        okld_prepared_block blocks[1];
        if (okld_prepared(fb.data, fb.size, &info, blocks, 0) != 0 || info.base != base || info.flags != 0
            || !same_bytes(info.digest, digest, 32)) {
            release_file(fb);
            return false;
        }
        s.prepared = fb;
        return true;
    };
    if (found()) return true;
    okld_why why{};
    const okld_u64 need = okld_prepare(bytes, size, base, digest, nullptr, 0, &why);
    if (need == 0) return false;
    void* buffer = kal_alloc(need, 16);
    if (!buffer) return false;
    const bool made = okld_prepare(bytes, size, base, digest, buffer, need, &why) == need
                   && write_whole(dir.d, name, buffer, need);
    kal_free(buffer, need, 16);
    return made && found();
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
    prepare_host(s, true);
    profile_phase("admitted");
    okld_module* m = nullptr;
    okld_why reason{};
    // AT THIS BOOT'S BASE WHERE THE RUNNER PREPARED IT, at the base it was
    // sealed with otherwise, and anywhere where neither can be had (0.4).
    int loaded = -1;
    if (prepare_local(s, bytes, size)) {
        loaded = okld_load_prepared(bytes, size, name, &s.host, s.prepared.data, s.prepared.size, &m, &reason);
        if (loaded != 0) { release_file(s.prepared); reason = okld_why{}; }
    }
    if (loaded != 0) loaded = okld_load(bytes, size, name, &s.host, &m, &reason);
    if (loaded != 0) {
        if (s.refusal[0]) text(why, cap) << name << ": " << s.refusal;
        else text(why, cap) << name << ": " << reason.text;
        return -1;
    }
    void* entry = okld_entry(m);
    if (!entry) { text(why, cap) << name << ": the image has no entry"; return -1; }
    // Where the entry image's bytes can be read again (0.2): the file run, at
    // the image's offset in it, or nowhere for bytes a program carries, which
    // stay where they are.
    {
        const auto* b = static_cast<const unsigned char*>(bytes);
        const bool fromRan = s.ran.data && b >= s.ran.data && b < s.ran.data + s.ran.size;
        profile_loaded(name, bytes, size, fromRan && s.ran_path[0] ? s.ran_path : nullptr,
                       fromRan ? static_cast<kal_u64>(b - s.ran.data) : 0);
    }
    profile_phase("loaded");
    profile_settle();
    release_ran(s);
    profile_begin_run();
    okld_initialise(m, &call_image, nullptr);
    profile_phase("initialised");
    const int status = reinterpret_cast<image_main>(entry)();
    profile_phase("main");
    okld_finalise(m, &call_image, nullptr);
    profile_finish();
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

bool locate_path(const char* path, kal_dir& dir, const char*& rest) { return locate(path, dir, rest); }

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

// A NAME'S SLOT, from a hash under which no two of the surface's names share
// one (build.mcpp, 0.4): one name compared, where every name was.
#include "surface_hash.inc"

extern "C" void* okrun_resolve(const char* name) {
    if (!name) return nullptr;
    unsigned h = 2166136261u ^ kResolveSeed;
    for (const char* c = name; *c; ++c) { h ^= static_cast<unsigned char>(*c); h *= 16777619u; }
    const unsigned short slot = kResolveSlot[h % kResolveSlots];
    if (slot == 0) return nullptr;
    unsigned long n = 0;
    const unsigned long i = slot - 1u;
    const binding* t = i < kResolveMain ? bindings(n) : space_bindings(n);
    const unsigned long k = i < kResolveMain ? i : i - kResolveMain;
    if (!t || k >= n || !same(t[k].name, name)) return nullptr;
    return t[k].address;
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
    g_search.ran = f;
    copy_text(g_search.ran_path, sizeof g_search.ran_path, path);
    const int status = okrun_run_bytes(f.data, f.size, path, argc, argv, options, why, cap);
    release_ran(g_search);
    return status;
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
    search        s;                  // `s.ran': the file it was read from, until it is loaded
};

namespace {

okrun_library* open_loaded(okrun_library* lib, const void* bytes, unsigned long long size, const char* name,
                           char* why, unsigned long long cap) {
    if (!admit(bytes, size, name, lib->s.options, why, cap)) return nullptr;
    prepare_host(lib->s, false);
    okld_why reason{};
    if (okld_load(bytes, size, name, &lib->s.host, &lib->module, &reason) != 0) {
        if (lib->s.refusal[0]) text(why, cap) << name << ": " << lib->s.refusal;
        else text(why, cap) << name << ": " << reason.text;
        return nullptr;
    }
    okld_initialise(lib->module, &call_image, nullptr);
    // The file a library was read from is released once it is loaded.
    release_ran(lib->s);
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
    release_ran(lib->s);
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
    lib->s.ran = f;
    copy_text(lib->s.ran_path, sizeof lib->s.ran_path, found);
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
