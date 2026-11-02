// THE BINDINGS WHILE A SNAPSHOT'S INITIALISERS RUN (0.4, docs/snapshot.md).
//
// A snapshot is an image's data, and the memory it obtained, as its initialisers
// left them, so that every later start maps them and runs no initialiser. What
// the initialisers may be given is what is the same at every start: memory, and
// what the implementation states of itself --- its granularities, its
// properties, its interfaces, its system's name --- which a start compares with
// the word the snapshot records (`environment_facts'). Everything else is the
// start's own: its arguments and named values, its streams and files, the time,
// randomness, other contexts. An initialiser that asks for any of it is refused,
// and no snapshot is made of the image: the refusal ends the runner that was
// making it (`seal_refused', src/run.cpp), and the program itself, which runs
// beside, never meets it.
#include <openkal.h>
#include "image_abi.h"
#include "runner.h"

namespace okrun {

namespace {

// THE ARENA: what the initialisers obtain, where every start that maps the
// snapshot finds it. Its addresses lie beside a boundary of 256 MiB after the
// image's span: a region, and any memory aligned to 64 KiB or more, at or above
// the boundary, aligned from the address itself as asked (an allocator aligns
// its regions so: mimalloc to 256 MiB); other memory below it, downward, while
// it does not reach the image, and above the regions otherwise. So the arena is
// one range with no hole an alignment opened before its first region, and the
// environment is asked for its addresses as it grows (kal_exec_alloc_at).
constexpr kal_u64 kPivot = 256ull << 20;
constexpr kal_u64 kMost = 1ull << 30;
constexpr kal_u64 kGrain = 65536;
kal_u64 g_floor = 0;            // the image's end: the arena lies above it
kal_u64 g_down = 0, g_up = 0;   // the next address below the boundary, and above
kal_u64 g_lo = 0, g_hi = 0;     // what the environment gave

kal_u64 round_up(kal_u64 v, kal_u64 a) { return (v + a - 1) & ~(a - 1); }
kal_u64 round_down(kal_u64 v, kal_u64 a) { return v & ~(a - 1); }

[[noreturn]] void exhausted(kal_uintptr size, kal_uintptr align) {
    static char why[200];
    char* o = why;
    auto put = [&](const char* t) { while (*t && o < why + sizeof why - 1) *o++ = *t++; };
    auto num = [&](kal_u64 v) { char d[24]; int n = 0; do { d[n++] = static_cast<char>('0' + v % 10); v /= 10; } while (v); while (n && o < why + sizeof why - 1) *o++ = d[--n]; };
    put("the initialisers asked for "); num(size); put(" bytes aligned to "); num(align);
    put(", and the arena, of "); num(g_hi - g_lo); put(" bytes, cannot hold them");
    *o = 0;
    seal_refused(why);
}

// [from, to) within what the environment gave, the arena extended to it.
bool hold(kal_u64 from, kal_u64 to) {
    from = round_down(from, kGrain);
    to = round_up(to, kGrain);
    const kal_u64 lo = from < g_lo ? from : g_lo, hi = to > g_hi ? to : g_hi;
    if (hi - lo > kMost) return false;
    if (from < g_lo) {
        if (kal_exec_alloc_at(reinterpret_cast<void*>(from), g_lo - from) != reinterpret_cast<void*>(from)) return false;
        g_lo = from;
    }
    if (to > g_hi) {
        if (kal_exec_alloc_at(reinterpret_cast<void*>(g_hi), to - g_hi) != reinterpret_cast<void*>(g_hi)) return false;
        g_hi = to;
    }
    return true;
}

void* take(kal_uintptr size, kal_uintptr align) {
    if (align < 16) align = 16;
    if (align & (align - 1)) exhausted(size, align);
    const kal_u64 n = round_up(size ? size : 1, 16);
    if (align < kGrain) {
        const kal_u64 at = round_down(g_down - n, align);
        if (g_down >= n && at >= g_floor && hold(at, g_down)) { g_down = at; return reinterpret_cast<void*>(at); }
    }
    const kal_u64 at = round_up(g_up, align);
    if (!hold(at, at + n)) exhausted(size, align);
    g_up = at + n;
    return reinterpret_cast<void*>(at);
}
void zero(void* p, kal_uintptr n) {
    auto* b = static_cast<volatile unsigned char*>(p);
    for (kal_uintptr i = 0; i < n; ++i) b[i] = 0;
}

OKRUN_IMAGE_ABI void* seal_kal_alloc(kal_uintptr size, kal_uintptr align) { return take(size, align); }
OKRUN_IMAGE_ABI void seal_kal_free(void*, kal_uintptr, kal_uintptr) {}
// A region is reserved, and every part of it backed, at once: the arena's
// memory is the program's. A part whose contents go is zero, as a part
// backed again after them reads.
OKRUN_IMAGE_ABI void* seal_kal_region_reserve(kal_uintptr size, kal_uintptr align, kal_uintptr) {
    const kal_uintptr g = kal_memory_granularity();
    return take(round_up(size, g), align > g ? align : g);
}
OKRUN_IMAGE_ABI int seal_kal_region_commit(void*, kal_uintptr) { return kal_ok; }
OKRUN_IMAGE_ABI int seal_kal_region_decommit(void* p, kal_uintptr n) { zero(p, n); return kal_ok; }
OKRUN_IMAGE_ABI int seal_kal_region_discard(void* p, kal_uintptr n) { zero(p, n); return kal_ok; }
OKRUN_IMAGE_ABI void seal_kal_region_release(void*, kal_uintptr) {}
// One context, named by a word no environment gives one: the start that maps
// the snapshot moves what the initialisers recorded of it to its own.
OKRUN_IMAGE_ABI kal_uintptr seal_kal_task_current(void) { return kSealContext; }
OKRUN_IMAGE_ABI void seal_kal_task_yield(void) {}
// No measurement: the start that maps the snapshot is measured, if it asks.
OKRUN_IMAGE_ABI int seal_kal_prof_active(void) { return 0; }

// FNV-1a, 64 bits.
struct fnv {
    kal_u64 h = 14695981039346656037ull;
    void bytes(const void* p, kal_uintptr n) {
        const auto* b = static_cast<const unsigned char*>(p);
        for (kal_uintptr i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    }
    void word(kal_u64 v) { bytes(&v, sizeof v); }
};

// THE NAMED VALUES THE INITIALISERS ASKED FOR, one name at a time: answered
// from the environment this runner was started with --- the program's own ---
// and recorded with a word of the answer, which a start compares with its own
// answer for the name (`seal_kept_holds'). Most are absent at every start: a
// library's switch for its own tests, read once into a constant.
struct asked_name { char name[128]; kal_u32 len; kal_intptr value_len; kal_u64 value_word; };
asked_name g_named[128];
unsigned g_named_count = 0;
char g_value[65536];

// What a start answers for a name: the value's length (negative: absent) and a
// word of its bytes; false where the value is longer than is compared.
bool answer_of(const char* name, kal_uintptr len, kal_intptr& value_len, kal_u64& word) {
    value_len = kal_env_var(name, len, g_value, sizeof g_value);
    fnv f;
    if (value_len > static_cast<kal_intptr>(sizeof g_value)) return false;
    if (value_len > 0) f.bytes(g_value, static_cast<kal_uintptr>(value_len));
    word = f.h;
    return true;
}

OKRUN_IMAGE_ABI kal_intptr seal_kal_env_var(const char* name, kal_uintptr len, char* out, kal_uintptr cap) {
    bool known = false;
    for (unsigned i = 0; i < g_named_count && !known; ++i) {
        const asked_name& a = g_named[i];
        known = a.len == len;
        for (kal_uintptr k = 0; known && k < len; ++k) known = a.name[k] == name[k];
    }
    if (!known) {
        if (len >= sizeof g_named[0].name || g_named_count == sizeof g_named / sizeof g_named[0])
            seal_refused("the initialisers asked for more named values, or a longer name, than a snapshot records");
        asked_name& a = g_named[g_named_count++];
        for (kal_uintptr k = 0; k < len; ++k) a.name[k] = name[k];
        a.len = static_cast<kal_u32>(len);
        if (!answer_of(name, len, a.value_len, a.value_word))
            seal_refused("an initialiser asked for a named value longer than a snapshot compares");
    }
    return kal_env_var(name, len, out, cap);
}

// THE START'S OWN ANSWERS THAT ARE THE SAME AT MOST STARTS: the processors and
// the cores a program may run on, which a program confined to part of the
// machine is told the part of, and the resource preference it was started
// with. An initialiser that asks for one is answered, the answer is folded into
// the snapshot's facts, and a start that would answer otherwise does not use
// the snapshot: a pool sized when the snapshot was made is sized right.
kal_u64 g_asked = 0;
constexpr kal_u64 kAskedParallelism = 1, kAskedCores = 2, kAskedResources = 4;
OKRUN_IMAGE_ABI kal_uintptr seal_kal_task_parallelism(void) { g_asked |= kAskedParallelism; return kal_task_parallelism(); }
OKRUN_IMAGE_ABI kal_uintptr seal_kal_task_cores(void) { g_asked |= kAskedCores; return kal_task_cores(); }
OKRUN_IMAGE_ABI int seal_kal_env_resources(void) { g_asked |= kAskedResources; return kal_env_resources(); }
OKRUN_IMAGE_ABI kal_u64 seal_kal_interfaces(void) { return own_interfaces(); }

// A fact of the implementation, answered as at any start.
template <auto F> struct fact;
template <class R, class... A, R (*F)(A...)>
struct fact<F> { OKRUN_IMAGE_ABI static R call(A... a) { return F(a...); } };

// Every other name: the snapshot is refused, naming it.
binding g_names[512];
unsigned long g_count = 0;
[[noreturn]] void asked(const char* name) {
    static char why[160];
    char* o = why;
    const char* const parts[] = { "an initialiser asked for ", name, ", which is the start's own" };
    for (const char* t : parts)
        while (*t && o < why + sizeof why - 1) *o++ = *t++;
    *o = 0;
    seal_refused(why);
}
template <unsigned long I> OKRUN_IMAGE_ABI void refuse() { asked(g_names[I].name); }

#define OKRUN_BIND(n, i)     { #n, reinterpret_cast<void*>(&refuse<i>) },
#define OKRUN_OWN(n, i)      OKRUN_BIND(n, i)
#define OKRUN_CALLBACK(n, i) OKRUN_BIND(n, i)
const binding g_main[] = {
#include "surface.inc"
};
#undef OKRUN_BIND
// openkal.space's names follow the others in `g_names'.
constexpr unsigned long kMain = sizeof g_main / sizeof g_main[0];
#define OKRUN_BIND(n, i)     { #n, reinterpret_cast<void*>(&refuse<kMain + i>) },
const binding g_space[] = {
#include "surface_space.inc"
};
static_assert(kMain + sizeof g_space / sizeof g_space[0] <= sizeof g_names / sizeof g_names[0]);

const binding g_allowed[] = {
    { "kal_alloc",              reinterpret_cast<void*>(&seal_kal_alloc) },
    { "kal_free",               reinterpret_cast<void*>(&seal_kal_free) },
    { "kal_region_reserve",     reinterpret_cast<void*>(&seal_kal_region_reserve) },
    { "kal_region_commit",      reinterpret_cast<void*>(&seal_kal_region_commit) },
    { "kal_region_decommit",    reinterpret_cast<void*>(&seal_kal_region_decommit) },
    { "kal_region_discard",     reinterpret_cast<void*>(&seal_kal_region_discard) },
    { "kal_region_release",     reinterpret_cast<void*>(&seal_kal_region_release) },
    { "kal_task_current",       reinterpret_cast<void*>(&seal_kal_task_current) },
    { "kal_task_yield",         reinterpret_cast<void*>(&seal_kal_task_yield) },
    { "kal_prof_active",        reinterpret_cast<void*>(&seal_kal_prof_active) },
    { "kal_task_parallelism",   reinterpret_cast<void*>(&seal_kal_task_parallelism) },
    { "kal_task_cores",         reinterpret_cast<void*>(&seal_kal_task_cores) },
    { "kal_env_resources",      reinterpret_cast<void*>(&seal_kal_env_resources) },
    { "kal_env_var",            reinterpret_cast<void*>(&seal_kal_env_var) },
    { "kal_interfaces",         reinterpret_cast<void*>(&seal_kal_interfaces) },
    { "kal_version",            reinterpret_cast<void*>(&fact<&::kal_version>::call) },
    { "kal_memory_granularity", reinterpret_cast<void*>(&fact<&::kal_memory_granularity>::call) },
    { "kal_exec_granularity",   reinterpret_cast<void*>(&fact<&::kal_exec_granularity>::call) },
    { "kal_exec_props",         reinterpret_cast<void*>(&fact<&::kal_exec_props>::call) },
    { "kal_region_props",       reinterpret_cast<void*>(&fact<&::kal_region_props>::call) },
    { "kal_time_props",         reinterpret_cast<void*>(&fact<&::kal_time_props>::call) },
    { "kal_time_monotonic_granularity", reinterpret_cast<void*>(&fact<&::kal_time_monotonic_granularity>::call) },
    { "kal_timeout_granularity", reinterpret_cast<void*>(&fact<&::kal_timeout_granularity>::call) },
    { "kal_random_props",       reinterpret_cast<void*>(&fact<&::kal_random_props>::call) },
    { "kal_process_props",      reinterpret_cast<void*>(&fact<&::kal_process_props>::call) },
    { "kal_task_props",         reinterpret_cast<void*>(&fact<&::kal_task_props>::call) },
    { "kal_net_props",          reinterpret_cast<void*>(&fact<&::kal_net_props>::call) },
    { "kal_datagram_props",     reinterpret_cast<void*>(&fact<&::kal_datagram_props>::call) },
    { "kal_prof_props",         reinterpret_cast<void*>(&fact<&::kal_prof_props>::call) },
    { "kal_debug_props",        reinterpret_cast<void*>(&fact<&::kal_debug_props>::call) },
    { "kal_fs_max_name",        reinterpret_cast<void*>(&fact<&::kal_fs_max_name>::call) },
    { "kal_env_system",         reinterpret_cast<void*>(&fact<&::kal_env_system>::call) },
};

void fill_names() {
    if (g_count) return;
    for (const binding& b : g_main) g_names[g_count++] = b;
    unsigned long space = 0;
    if (space_bindings(space) && space)
        for (const binding& b : g_space) g_names[g_count++] = b;
    for (const binding& a : g_allowed)
        for (unsigned long i = 0; i < g_count; ++i)
            if (same(g_names[i].name, a.name)) g_names[i].address = a.address;
    // kal_space_props is a fact where the interface is bound.
    for (unsigned long i = kMain; i < g_count; ++i)
        if (same(g_names[i].name, "kal_space_props")) g_names[i].address = space_props_binding();
}

}  // namespace

void seal_begin(kal_u64 image_end) {
    fill_names();
    g_floor = round_up(image_end, kGrain);
    g_down = g_up = g_lo = g_hi = round_up(g_floor, kPivot);
}

void seal_arena(kal_u64& lo, kal_u64& hi) { lo = g_lo; hi = g_hi; }

void* seal_resolve(const char* name) {
    fill_names();
    for (unsigned long i = 0; i < g_count; ++i)
        if (same(g_names[i].name, name)) return g_names[i].address;
    return nullptr;
}

bool seal_is_binding(kal_uintptr word) {
    static kal_uintptr sorted[sizeof g_names / sizeof g_names[0]];
    static unsigned long n = 0;
    if (n == 0) {
        fill_names();
        for (unsigned long i = 0; i < g_count; ++i) {
            kal_uintptr a = reinterpret_cast<kal_uintptr>(g_names[i].address);
            unsigned long j = n++;
            for (; j > 0 && sorted[j - 1] > a; --j) sorted[j] = sorted[j - 1];
            sorted[j] = a;
        }
    }
    unsigned long a = 0, b = n;
    while (a < b) { const unsigned long k = (a + b) / 2; if (sorted[k] < word) a = k + 1; else b = k; }
    return a < n && sorted[a] == word;
}

kal_u64 seal_asked() { return g_asked; }

// THE NAMED VALUES ASKED FOR, as the bytes kept with the snapshot: for each, a
// kal_u32 length of the name, a kal_u32 zero, the value's length as a kal_i64
// (negative: absent), a word of the value, and the name, to a multiple of 8.
kal_u64 seal_kept(void* out, kal_u64 cap) {
    kal_u64 n = 0;
    auto* o = static_cast<unsigned char*>(out);
    auto put = [&](const void* p, kal_u64 k) {
        if (o && n + k <= cap) for (kal_u64 i = 0; i < k; ++i) o[n + i] = static_cast<const unsigned char*>(p)[i];
        n += k;
    };
    for (unsigned i = 0; i < g_named_count; ++i) {
        const asked_name& a = g_named[i];
        const kal_u32 zero = 0;
        const kal_u64 value_len = static_cast<kal_u64>(static_cast<long long>(a.value_len));
        put(&a.len, 4); put(&zero, 4); put(&value_len, 8); put(&a.value_word, 8);
        put(a.name, a.len);
        const unsigned char pad[8] = {};
        put(pad, (8 - a.len % 8) % 8);
    }
    return n;
}

// Whether this start answers every named value the snapshot's initialisers
// asked for as the program that made it answered.
bool seal_kept_holds(const void* kept, kal_u64 size) {
    const auto* b = static_cast<const unsigned char*>(kept);
    kal_u64 at = 0;
    auto get = [&](void* p, kal_u64 k) {
        if (at + k > size) return false;
        for (kal_u64 i = 0; i < k; ++i) static_cast<unsigned char*>(p)[i] = b[at + i];
        at += k;
        return true;
    };
    while (at < size) {
        kal_u32 len = 0, zero = 0;
        kal_u64 value_len = 0, word = 0;
        if (!get(&len, 4) || !get(&zero, 4) || !get(&value_len, 8) || !get(&word, 8) || len >= 128 || at + len > size)
            return false;
        kal_intptr now_len = 0;
        kal_u64 now_word = 0;
        if (!answer_of(reinterpret_cast<const char*>(b + at), len, now_len, now_word)) return false;
        if (static_cast<kal_u64>(static_cast<long long>(now_len)) != value_len || now_word != word) return false;
        at += len + (8 - len % 8) % 8;
    }
    return true;
}

// WHAT THE IMPLEMENTATION STATES OF ITSELF, as one word: every fact the
// bindings above answer, in one order, and the start's own answers `asked'
// names. A snapshot made under another word --- another implementation,
// another version of it, another machine's granularity, a start confined to
// other processors --- is not used.
kal_u32 environment_facts(kal_u64 asked) {
    fnv f;
    f.bytes("okrun snapshot 1", 16);
    f.word(own_interfaces());
    f.word(kal_version());
    f.word(kal_memory_granularity());
    f.word(kal_exec_granularity());
    f.word(kal_exec_props());
    f.word(kal_region_props());
    f.word(kal_time_props());
    f.word(kal_time_monotonic_granularity());
    f.word(kal_timeout_granularity());
    f.word(kal_random_props());
    f.word(kal_process_props());
    f.word(kal_task_props());
    f.word(kal_net_props());
    f.word(kal_datagram_props());
    f.word(kal_prof_props());
    f.word(kal_debug_props());
    f.word(kal_fs_max_name());
    f.word(space_props());
    f.word(asked);
    if (asked & kAskedParallelism) f.word(kal_task_parallelism());
    if (asked & kAskedCores) f.word(kal_task_cores());
    if (asked & kAskedResources) f.word(static_cast<kal_u64>(kal_env_resources()));
    char system[32];
    const kal_intptr n = kal_env_system(system, sizeof system);
    if (n > 0) f.bytes(system, n < static_cast<kal_intptr>(sizeof system) ? static_cast<kal_uintptr>(n) : sizeof system);
    return static_cast<kal_u32>(f.h ^ (f.h >> 32));
}

}  // namespace okrun
