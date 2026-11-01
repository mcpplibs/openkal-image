// A measurement of an image, and the names of its addresses (openkal-image 0.2).
//
// THE LOADER IS WHERE BOTH BELONG (SPEC 12.3). It binds every name an image
// calls across openkal, so it can count those calls without the image's help;
// it read the image's file, so it can name an address from the symbol table the
// image never placed in memory; and it is where the program ends, so it is
// where what was measured is written. openkal.prof lets the program add what
// only it knows (its own counters and phases) and openkal.debug lets it ask for
// a name; both are answered here.
//
// WHAT IS MEASURED IS WHAT WAS ASKED FOR, AND NOTHING WHEN NOTHING WAS.
// OKRUN_PROF (or `okrun --prof', which sets the same) names any of
//
//     calls      each name an image imports is bound through an entry that
//                counts its calls and their time, by name
//     counters   the counters and phases the program registers are kept
//     perfmap    /tmp/perf-<pid>.map is written, where this system's profiler
//                (perf) reads the names of an anonymous region's addresses
//
// separated by commas, and `:<directory>' after them receives the report,
// `okprof-<id>.json' (the working directory otherwise). Unset, an image is bound
// as it always was and `kal_prof_active' answers zero.
#include <openkal.h>
#include <okld.h>
#include "runner.h"

extern "C" void okrun_profile(const char* spec);

namespace okrun {
namespace {

kal_uintptr length(const char* s) { kal_uintptr n = 0; while (s && s[n]) ++n; return n; }
void copy_text(char* d, kal_uintptr cap, const char* s, kal_uintptr n) {
    if (cap == 0) return;
    kal_uintptr i = 0;
    for (; i < n && i + 1 < cap && s[i]; ++i) d[i] = s[i];
    d[i] = 0;
}
bool same_text(const char* a, kal_uintptr an, const char* b) {
    kal_uintptr i = 0;
    for (; i < an && b[i]; ++i) if (a[i] != b[i]) return false;
    return i == an && b[i] == 0;
}
bool contains(const char* s, kal_uintptr n, const char* word) {
    const kal_uintptr w = length(word);
    for (kal_uintptr i = 0; i + w <= n; ++i) {
        kal_uintptr k = 0;
        while (k < w && s[i + k] == word[k]) ++k;
        if (k == w && (i + w == n || s[i + w] == ',' || s[i + w] == ':') && (i == 0 || s[i - 1] == ',')) return true;
    }
    return false;
}

// --- one lock, held briefly ------------------------------------------------------
volatile int g_lock = 0;
void lock() { while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE)) kal_task_yield(); }
void unlock() { __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE); }

// --- what was asked for ------------------------------------------------------------
enum : int { asked_active = 1, asked_calls = 2, asked_counters = 4, asked_perfmap = 8 };
int g_mode = -1;                 // -1: not read yet
char g_dir[512] = {};
kal_u64 g_started = 0;

void read_spec(const char* spec, kal_uintptr n) {
    int mode = 0;
    if (n > 0) {
        mode = asked_active;
        if (contains(spec, n, "calls")) mode |= asked_calls;
        if (contains(spec, n, "counters")) mode |= asked_counters;
        if (contains(spec, n, "perfmap")) mode |= asked_perfmap;
        if (mode == asked_active) mode |= asked_calls | asked_counters;   // a bare `1'
        for (kal_uintptr i = 0; i < n; ++i)
            if (spec[i] == ':') { copy_text(g_dir, sizeof g_dir, spec + i + 1, n - i - 1); break; }
    }
    g_started = kal_time_monotonic();
    __atomic_store_n(&g_mode, mode, __ATOMIC_RELEASE);
}

int mode() {
    int m = __atomic_load_n(&g_mode, __ATOMIC_ACQUIRE);
    if (m >= 0) return m;
    static const char name[] = "OKRUN_PROF";
    char spec[600];
    const kal_intptr n = kal_env_var(name, sizeof name - 1, spec, sizeof spec - 1);
    read_spec(spec, n > 0 && n < static_cast<kal_intptr>(sizeof spec) ? static_cast<kal_uintptr>(n) : 0);
    return __atomic_load_n(&g_mode, __ATOMIC_ACQUIRE);
}

// --- calls ---------------------------------------------------------------------------
kal_u64 g_calls[kProfiledNames];
kal_u64 g_call_ns[kProfiledNames];

// --- counters and phases --------------------------------------------------------------
struct counter { char name[96]; const volatile kal_u64* cell; };
constexpr unsigned kCounters = 512;
counter g_counters[kCounters];
unsigned g_counter_count = 0;

struct phase { char name[96]; kal_u64 count, ns; };
constexpr unsigned kPhases = 256;
phase g_phases[kPhases];
unsigned g_phase_count = 0;

// The phases open on each context: the context's word (kal_task_current), and
// a stack of (phase, start). A table rather than thread-local storage, because
// this library may be linked into a program that brings no C++ run-time to
// allocate it.
struct open_phase { unsigned phase; kal_u64 start; };
struct context_phases { kal_uintptr context; unsigned depth; open_phase stack[16]; };
constexpr unsigned kContexts = 512;
context_phases g_open[kContexts];

unsigned phase_of(const char* name, kal_uintptr len) {
    for (unsigned i = 0; i < g_phase_count; ++i) if (same_text(name, len, g_phases[i].name)) return i;
    if (g_phase_count == kPhases) return kPhases;
    copy_text(g_phases[g_phase_count].name, sizeof g_phases[0].name, name, len);
    return g_phase_count++;
}

context_phases* context_of(kal_uintptr me) {
    context_phases* free_slot = nullptr;
    for (auto& c : g_open) {
        if (c.context == me) return &c;
        if (!free_slot && c.context == 0) free_slot = &c;
    }
    if (free_slot) { free_slot->context = me; free_slot->depth = 0; }
    return free_slot;
}

// --- images, and the names of their addresses ------------------------------------------
struct symbol { kal_u64 value, size; kal_u32 name; };
struct image_record {
    char name[256];
    const void* bytes;          // bytes that stay where they are, or null
    kal_u64 size;
    char source[512];           // a file to read them again from, or empty
    kal_u64 offset;
    const void* at_hand;        // bytes valid until the runner releases them
    bool mapped;                // its lines are in the perf map
    symbol* symbols;            // made at the first question, sorted by value
    kal_u64 symbol_count;
    char* names;
    kal_u64 names_size;
    bool tried;
};
constexpr unsigned kImages = 64;
image_record g_images[kImages];
unsigned g_image_count = 0;

struct gather { symbol* symbols; kal_u64 count, cap; char* names; kal_u64 used, names_cap; };

void count_symbol(okld_u64, okld_u64, const char* name, void* ctx) {
    auto* g = static_cast<gather*>(ctx);
    ++g->count;
    g->names_cap += length(name) + 1;
}
void keep_symbol(okld_u64 value, okld_u64 size, const char* name, void* ctx) {
    auto* g = static_cast<gather*>(ctx);
    if (g->count == g->cap) return;
    const kal_uintptr n = length(name);
    if (g->used + n + 1 > g->names_cap) return;
    g->symbols[g->count++] = symbol{ value, size, static_cast<kal_u32>(g->used) };
    for (kal_uintptr i = 0; i <= n; ++i) g->names[g->used + i] = name[i];
    g->used += n + 1;
}

void sift(symbol* a, kal_u64 start, kal_u64 end) {
    kal_u64 root = start;
    while (2 * root + 1 < end) {
        kal_u64 child = 2 * root + 1;
        if (child + 1 < end && a[child].value < a[child + 1].value) ++child;
        if (a[root].value >= a[child].value) return;
        const symbol t = a[root]; a[root] = a[child]; a[child] = t;
        root = child;
    }
}
void sort_symbols(symbol* a, kal_u64 n) {
    if (n < 2) return;
    for (kal_u64 i = n / 2; i-- > 0;) sift(a, i, n);
    for (kal_u64 end = n - 1; end > 0; --end) {
        const symbol t = a[0]; a[0] = a[end]; a[end] = t;
        sift(a, 0, end);
    }
}

void index_symbols(image_record& r, const void* bytes, kal_u64 size) {
    gather g{};
    okld_symbols(bytes, size, &count_symbol, &g);
    if (g.count == 0) return;
    g.symbols = static_cast<symbol*>(kal_alloc(g.count * sizeof(symbol), 16));
    g.names = static_cast<char*>(kal_alloc(g.names_cap, 16));
    if (!g.symbols || !g.names) {
        if (g.symbols) kal_free(g.symbols, g.count * sizeof(symbol), 16);
        if (g.names) kal_free(g.names, g.names_cap, 16);
        return;
    }
    g.cap = g.count;
    g.count = 0;
    okld_symbols(bytes, size, &keep_symbol, &g);
    sort_symbols(g.symbols, g.count);
    r.symbols = g.symbols;
    r.symbol_count = g.count;
    r.names = g.names;
    r.names_size = g.names_cap;
}

// The bytes of an image again: those that stayed, or its file's region.
bool reread(image_record& r, void*& region, kal_uintptr& region_len, const void*& bytes) {
    region = nullptr;
    region_len = 0;
    if (r.bytes) { bytes = r.bytes; return true; }
    if (!r.source[0]) return false;
    kal_dir dir{};
    const char* rest = nullptr;
    if (!locate_path(r.source, dir, rest)) return false;
    kal_file f{};
    if (kal_fs_open(dir, rest, length(rest), KAL_OPEN_READ, &f) != kal_ok) return false;
    const kal_u64 aligned = r.offset & ~(KAL_MAP_ALIGNMENT - 1);
    region_len = static_cast<kal_uintptr>(r.offset - aligned + r.size);
    const int e = kal_map_file(f, aligned, region_len, 0, &region);
    kal_fs_close_file(f);
    if (e != kal_ok) { region = nullptr; return false; }
    bytes = static_cast<const unsigned char*>(region) + (r.offset - aligned);
    return true;
}

image_record* record_of(const char* name) {
    for (unsigned i = 0; i < g_image_count; ++i)
        if (same_text(name, length(name), g_images[i].name)) return &g_images[i];
    return nullptr;
}

struct find_base { const char* name; void* base; };
int base_of(void* base, const void*, okld_u32, const char* name, void* ctx) {
    auto* f = static_cast<find_base*>(ctx);
    if (!same_text(f->name, length(f->name), name)) return 0;
    f->base = base;
    return 1;
}

// --- writing ---------------------------------------------------------------------------
struct out_buffer {
    char* data = nullptr; kal_uintptr used = 0, cap = 0;
    void put(const char* s, kal_uintptr n) {
        if (used + n > cap) {
            kal_uintptr grown = cap ? cap * 2 : 65536;
            while (grown < used + n) grown *= 2;
            char* d = static_cast<char*>(kal_alloc(grown, 16));
            if (!d) return;
            for (kal_uintptr i = 0; i < used; ++i) d[i] = data[i];
            if (data) kal_free(data, cap, 16);
            data = d; cap = grown;
        }
        for (kal_uintptr i = 0; i < n; ++i) data[used + i] = s[i];
        used += n;
    }
    void put(const char* s) { put(s, length(s)); }
    void number(kal_u64 v, int base = 10) {
        char b[24]; int n = 0;
        do { const int d = static_cast<int>(v % static_cast<kal_u64>(base)); b[n++] = static_cast<char>(d < 10 ? '0' + d : 'a' + d - 10); v /= static_cast<kal_u64>(base); } while (v);
        char r[24];
        for (int i = 0; i < n; ++i) r[i] = b[n - 1 - i];
        put(r, static_cast<kal_uintptr>(n));
    }
    void quoted(const char* s) {
        put("\"");
        for (; s && *s; ++s) {
            if (*s == '"' || *s == '\\') { const char e[2] = { '\\', *s }; put(e, 2); }
            else if (static_cast<unsigned char>(*s) < 0x20) put("?");
            else put(s, 1);
        }
        put("\"");
    }
    void release() { if (data) kal_free(data, cap, 16); data = nullptr; used = cap = 0; }
};

bool write_file(const char* path, const out_buffer& b) {
    kal_dir dir{};
    const char* rest = nullptr;
    if (!locate_path(path, dir, rest)) return false;
    kal_file f{};
    if (kal_fs_open(dir, rest, length(rest), KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f) != kal_ok)
        return false;
    const kal_intptr w = kal_stream_write(kal_fs_stream(f), b.data, b.used);
    kal_fs_close_file(f);
    return w == static_cast<kal_intptr>(b.used);
}

kal_u64 own_id() {
    kal_process self{};
    if (kal_process_self(&self) != kal_ok) return 0;
    kal_program_info info{};
    info.self_size = sizeof info;
    kal_process_info(self, KAL_PINFO_ID, &info);
    kal_process_close(self);
    return info.id;
}

bool on_linux() {
    char system[16];
    const kal_intptr n = kal_env_system(system, sizeof system);
    return n == 5 && same_text(system, 5, "linux");
}

void write_perf_map(image_record& r, const void* bytes, kal_u64 size) {
    find_base fb{ r.name, nullptr };
    okld_iterate(&base_of, &fb);
    if (!fb.base) return;
    index_symbols(r, bytes, size);
    if (!r.symbols) return;
    out_buffer b;
    for (kal_u64 i = 0; i < r.symbol_count; ++i) {
        b.number(reinterpret_cast<kal_u64>(fb.base) + r.symbols[i].value, 16);
        b.put(" ");
        b.number(r.symbols[i].size ? r.symbols[i].size : 1, 16);
        b.put(" ");
        b.put(r.names + r.symbols[i].name);
        b.put("\n");
    }
    // Appended: each image a run loads adds its lines.
    char path[64] = "/tmp/perf-";
    kal_uintptr at = 10;
    kal_u64 id = own_id();
    char digits[24]; int nd = 0;
    do { digits[nd++] = static_cast<char>('0' + id % 10); id /= 10; } while (id);
    while (nd) path[at++] = digits[--nd];
    const char tail[] = ".map";
    for (kal_uintptr i = 0; i < sizeof tail; ++i) path[at + i] = tail[i];
    kal_dir dir{};
    const char* rest = nullptr;
    if (locate_path(path, dir, rest)) {
        kal_file f{};
        if (kal_fs_open(dir, rest, length(rest), KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_APPEND, &f) == kal_ok) {
            kal_stream_write(kal_fs_stream(f), b.data, b.used);
            kal_fs_close_file(f);
        }
    }
    b.release();
}

bool g_finished = false;

}  // namespace

bool profile_active() { return (mode() & asked_active) != 0; }
bool profile_calls() { return (mode() & asked_calls) != 0; }

void record_call(unsigned long index, kal_u64 ns) {
    if (index >= kProfiledNames) return;
    __atomic_fetch_add(&g_calls[index], 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_call_ns[index], ns, __ATOMIC_RELAXED);
}

int profile_counter(const char* name, kal_uintptr len, const volatile kal_u64* cell) {
    if (!(mode() & asked_counters) || !name || !cell) return kal_ok;
    lock();
    if (g_counter_count == kCounters) { unlock(); return kal_err_no_memory; }
    copy_text(g_counters[g_counter_count].name, sizeof g_counters[0].name, name, len);
    g_counters[g_counter_count].cell = cell;
    ++g_counter_count;
    unlock();
    return kal_ok;
}

void profile_mark(const char* name, kal_uintptr len, int begin) {
    if (!(mode() & asked_counters) || !name) return;
    const kal_u64 now = kal_time_monotonic();
    const kal_uintptr me = kal_task_current();
    lock();
    const unsigned p = phase_of(name, len);
    context_phases* c = p < kPhases ? context_of(me) : nullptr;
    if (c) {
        if (begin) {
            if (c->depth < 16) c->stack[c->depth++] = open_phase{ p, now };
        } else {
            for (unsigned d = c->depth; d-- > 0;) {
                if (c->stack[d].phase != p) continue;
                g_phases[p].count += 1;
                g_phases[p].ns += now - c->stack[d].start;
                c->depth = d;
                break;
            }
            if (c->depth == 0) c->context = 0;
        }
    }
    unlock();
}

void profile_loaded(const char* name, const void* bytes, kal_u64 size, const char* source, kal_u64 offset) {
    lock();
    image_record* r = record_of(name);
    if (!r && g_image_count < kImages) r = &g_images[g_image_count++];
    if (r) {
        *r = image_record{};
        copy_text(r->name, sizeof r->name, name, length(name));
        r->bytes = source ? nullptr : bytes;
        r->at_hand = bytes;
        r->size = size;
        if (source) copy_text(r->source, sizeof r->source, source, length(source));
        r->offset = offset;
    }
    unlock();
}

// The images loaded so far, while their bytes are at hand: a perf map's lines
// are written for each (their places are known once they are loaded).
void profile_settle() {
    const bool map = (mode() & asked_perfmap) && on_linux();
    for (unsigned i = 0; i < g_image_count; ++i) {
        image_record& r = g_images[i];
        if (!r.at_hand) continue;
        if (map && !r.mapped) {
            find_base fb{ r.name, nullptr };
            okld_iterate(&base_of, &fb);
            if (!fb.base) continue;   // not loaded yet; asked again later
            write_perf_map(r, r.at_hand, r.size);
            r.mapped = true;
        }
        r.at_hand = r.bytes;
    }
}

kal_intptr symbolize(kal_uintptr address, char* out, kal_uintptr cap, kal_uintptr* start) {
    okld_module* m = okld_containing(reinterpret_cast<const void*>(address));
    if (!m) return -kal_err_not_found;
    const char* name = okld_name(m);
    const kal_u64 base = reinterpret_cast<kal_u64>(okld_base(m));
    lock();
    image_record* r = name ? record_of(name) : nullptr;
    if (r && !r->tried) {
        r->tried = true;
        void* region = nullptr; kal_uintptr region_len = 0; const void* bytes = nullptr;
        if (reread(*r, region, region_len, bytes)) {
            if (!r->symbols) index_symbols(*r, bytes, r->size);
            if (region) kal_map_release(region, region_len);
        }
    }
    if (!r || !r->symbols) { unlock(); return -kal_err_not_found; }
    const kal_u64 at = address - base;
    kal_u64 lo = 0, hi = r->symbol_count;
    while (lo < hi) {   // the last symbol whose value is at or below `at'
        const kal_u64 mid = lo + (hi - lo) / 2;
        if (r->symbols[mid].value <= at) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) { unlock(); return -kal_err_not_found; }
    const symbol& s = r->symbols[lo - 1];
    if (s.size && at >= s.value + s.size) { unlock(); return -kal_err_not_found; }
    const char* text = r->names + s.name;
    const kal_uintptr n = length(text);
    for (kal_uintptr i = 0; out && i < n && i < cap; ++i) out[i] = text[i];
    if (start) *start = static_cast<kal_uintptr>(base + s.value);
    unlock();
    return static_cast<kal_intptr>(n);
}

// THE REPORT, written once, where the program ends.
void profile_finish() {
    if (!(mode() & asked_active)) return;
    lock();
    if (g_finished) { unlock(); return; }
    g_finished = true;
    unlock();
    out_buffer b;
    b.put("{\n  \"format\": \"okprof-1\",\n  \"image\": ");
    b.quoted(g_image_count ? g_images[0].name : "");
    b.put(",\n  \"id\": ");
    const kal_u64 id = own_id();
    b.number(id);
    b.put(",\n  \"wall_ns\": ");
    b.number(kal_time_monotonic() - g_started);
    b.put(",\n  \"calls\": [");
    unsigned long count = 0;
    const binding* t = bindings(count);
    bool first = true;
    for (unsigned long i = 0; i < count && i < kProfiledNames; ++i) {
        if (!g_calls[i]) continue;
        b.put(first ? "\n    { \"name\": " : ",\n    { \"name\": ");
        first = false;
        b.quoted(t[i].name);
        b.put(", \"count\": "); b.number(g_calls[i]);
        b.put(", \"ns\": "); b.number(g_call_ns[i]);
        b.put(" }");
    }
    b.put(first ? "],\n  \"counters\": [" : "\n  ],\n  \"counters\": [");
    first = true;
    for (unsigned i = 0; i < g_counter_count; ++i) {
        b.put(first ? "\n    { \"name\": " : ",\n    { \"name\": ");
        first = false;
        b.quoted(g_counters[i].name);
        b.put(", \"value\": "); b.number(*g_counters[i].cell);
        b.put(" }");
    }
    b.put(first ? "],\n  \"phases\": [" : "\n  ],\n  \"phases\": [");
    first = true;
    for (unsigned i = 0; i < g_phase_count; ++i) {
        b.put(first ? "\n    { \"name\": " : ",\n    { \"name\": ");
        first = false;
        b.quoted(g_phases[i].name);
        b.put(", \"count\": "); b.number(g_phases[i].count);
        b.put(", \"ns\": "); b.number(g_phases[i].ns);
        b.put(" }");
    }
    b.put(first ? "]\n}\n" : "\n  ]\n}\n");
    char path[700];
    kal_uintptr at = 0;
    if (g_dir[0]) { copy_text(path, sizeof path - 64, g_dir, length(g_dir)); at = length(path); path[at++] = '/'; }
    const char stem[] = "okprof-";
    for (kal_uintptr i = 0; i + 1 < sizeof stem; ++i) path[at++] = stem[i];
    char digits[24]; int nd = 0;
    kal_u64 v = id;
    do { digits[nd++] = static_cast<char>('0' + v % 10); v /= 10; } while (v);
    while (nd) path[at++] = digits[--nd];
    const char tail[] = ".json";
    for (kal_uintptr i = 0; i < sizeof tail; ++i) path[at + i] = tail[i];
    write_file(path, b);
    b.release();
}

}  // namespace okrun

// `okrun --prof=<spec>' and a program that carries an image: what OKRUN_PROF
// would have said, stated before the image is entered.
extern "C" void okrun_profile(const char* spec) {
    okrun::read_spec(spec ? spec : "", okrun::length(spec));
}
