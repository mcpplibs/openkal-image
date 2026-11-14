// Loading an image (SPEC clause 12.3): map, relocate, bind, publish; and the
// record of what is loaded, for `dl_iterate_phdr', `dladdr' and a debugger.
#include <okld.h>
#include "image.h"
#include "debug_image.h"

namespace {

using namespace okld;

struct okld_module_rec;

}  // namespace

struct okld_module {
    okld_module*      next = nullptr;         // every loaded module
    const okld_host*  host = nullptr;
    unsigned char*    base = nullptr;
    elf::u64          span = 0;
    // The program headers as the image states them, of its class: within the
    // mapped image, or `own_phdr', a copy, when no segment holds them.
    const void*       phdr = nullptr;
    unsigned char*    own_phdr = nullptr;
    elf::u32          phnum = 0, phentsize = 0;
    elf::u64          entry = 0;
    char              name[256] = {};
    okld_module*      needed[16] = {};
    okld_size         needed_count = 0;
    int               references = 1;
    bool              initialised = false;
    bool              finalised = false;
    // Within the mapped image, from its dynamic table, of the image's class.
    bool                 wide = true;
    const unsigned char* symtab = nullptr;
    const char*       strtab = nullptr;
    elf::u64          strsz = 0;
    const elf::u32*   hash = nullptr;         // DT_HASH
    const elf::u32*   gnu_hash = nullptr;     // DT_GNU_HASH
    elf::u64          init = 0, fini = 0, init_array = 0, init_arraysz = 0, fini_array = 0, fini_arraysz = 0;
    // The relocation tables, within the mapped image (okld_bound_imports).
    elf::u64          rela = ~0ull, relasz = 0, jmprel = ~0ull, pltrelsz = 0;
    elf::u16          machine = 0;
    void*             debug_entry = nullptr;  // the GDB JIT record
    void*             debug_copy = nullptr;
    okld_size         debug_size = 0;
};

// --- the GDB JIT interface -----------------------------------------------------
//
// A debugger sets a breakpoint on `__jit_debug_register_code' and reads the
// descriptor; each entry is an object file whose addresses are where the image
// is. gdb and lldb both read it (lldb: `settings set plugin.jit-loader.gdb.enable on').
extern "C" {
struct jit_code_entry { jit_code_entry* next; jit_code_entry* prev; const char* symfile_addr; unsigned long long symfile_size; };
struct jit_descriptor { unsigned version; unsigned action_flag; jit_code_entry* relevant_entry; jit_code_entry* first_entry; };
[[gnu::used]] jit_descriptor __jit_debug_descriptor = { 1, 0, nullptr, nullptr };
[[gnu::noinline, gnu::used]] void __jit_debug_register_code() { __asm__ __volatile__("" ::: "memory"); }
}

namespace {

okld_module* g_modules = nullptr;
volatile int g_lock = 0;

void lock() { while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE)) {} }
void unlock() { __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE); }

// Bytes written as data and then executed: the instruction cache must see
// them. x86-64 keeps the two coherent; AArch64 does not, and the maintenance
// is written out because no library is here to call.
//
// THE LINE SIZE IS NOT READ FROM CTR_EL0. One system traps a read of it at
// user level, and the program died of SIGILL there before its first
// instruction ran (measured on macos-arm64). The maintenance instructions
// themselves are permitted on every system this runs upon, and a stride of 32
// bytes --- below any line size an AArch64 core has --- reaches every line at
// the cost of repeating some.
void sync_instructions(unsigned char* from, unsigned char* to) {
#if defined(__aarch64__)
    constexpr unsigned long long line = 32;
    const auto b = reinterpret_cast<unsigned long long>(from), e = reinterpret_cast<unsigned long long>(to);
    for (auto p = b & ~(line - 1); p < e; p += line) __asm__ __volatile__("dc cvau, %0" :: "r"(p) : "memory");
    __asm__ __volatile__("dsb ish" ::: "memory");
    for (auto p = b & ~(line - 1); p < e; p += line) __asm__ __volatile__("ic ivau, %0" :: "r"(p) : "memory");
    __asm__ __volatile__("dsb ish\n\tisb" ::: "memory");
#else
    (void)from; (void)to;
#endif
}

elf::u64 round_up(elf::u64 v, elf::u64 g) { return (v + g - 1) & ~(g - 1); }
elf::u64 round_down(elf::u64 v, elf::u64 g) { return v & ~(g - 1); }

// The alignment of an offset into a file that is mapped: openkal's
// KAL_MAP_ALIGNMENT, to which every loadable segment is aligned (SPEC 12.2).
constexpr elf::u64 file_alignment = 65536;

// The parts of the span relocations may write: the writable segments.
struct writable {
    elf::u64 from[8] = {}, to[8] = {};
    unsigned count = 0;
    bool holds(elf::u64 at, elf::u64 bytes) const {
        for (unsigned k = 0; k < count; ++k)
            if (at >= from[k] && at <= to[k] && bytes <= to[k] - at) return true;
        return false;
    }
};

void say(okld_why* why, const char* a, const char* b = nullptr, const char* c = nullptr) {
    if (!why) return;
    sentence s(why->text, sizeof why->text);
    s << a; if (b) s << b; if (c) s << c;
}

elf::u32 gnu_hash(const char* s) { elf::u32 h = 5381; for (; *s; ++s) h = h * 33 + static_cast<unsigned char>(*s); return h; }
elf::u32 sysv_hash(const char* s) {
    elf::u32 h = 0;
    for (; *s; ++s) { h = (h << 4) + static_cast<unsigned char>(*s); const elf::u32 g = h & 0xf0000000u; if (g) h ^= g >> 24; h &= ~g; }
    return h;
}

// A symbol of a module's dynamic table, widened from its class.
elf::sym symbol_of(const okld_module* m, elf::u32 index) {
    if (m->wide) {
        elf::sym s;
        copy(&s, m->symtab + static_cast<elf::u64>(index) * sizeof(elf::sym), sizeof s);
        return s;
    }
    elf::sym32 t;
    copy(&t, m->symtab + static_cast<elf::u64>(index) * sizeof(elf::sym32), sizeof t);
    return elf::sym{ t.name, t.info, t.other, t.shndx, t.value, t.size };
}

// A RELA relocation of a table in the mapped image, widened from its class.
elf::rela relocation_of(const unsigned char* table, elf::u64 k, bool wide) {
    if (wide) {
        elf::rela r;
        copy(&r, table + k * sizeof(elf::rela), sizeof r);
        return r;
    }
    elf::rela32 r;
    copy(&r, table + k * sizeof(elf::rela32), sizeof r);
    return elf::rela{ r.offset, elf::r_info(r.info >> 8, r.info & 0xff), r.addend };
}

// An exported name of a module: defined, not local.
void* lookup(const okld_module* m, const char* name) {
    auto defined = [&](elf::u32 index) -> void* {
        const auto s = symbol_of(m, index);
        if (s.shndx == elf::shn_undef || elf::st_bind(s.info) == elf::stb_local || !s.name) return nullptr;
        if (s.name >= m->strsz || !equal(m->strtab + s.name, name)) return nullptr;
        return s.shndx == elf::shn_abs ? reinterpret_cast<void*>(s.value) : m->base + s.value;
    };
    if (m->gnu_hash) {
        const elf::u32 nbuckets = m->gnu_hash[0], symoffset = m->gnu_hash[1], bloom = m->gnu_hash[2];
        const auto* buckets = m->gnu_hash + 4 + bloom * (m->wide ? 2 : 1);   // bloom words of the class
        const auto* chain = buckets + nbuckets;
        const elf::u32 h = gnu_hash(name);
        for (elf::u32 i = buckets[h % nbuckets]; i >= symoffset && i != 0; ++i) {
            const elf::u32 c = chain[i - symoffset];
            if ((c | 1) == (h | 1)) if (void* p = defined(i)) return p;
            if (c & 1) break;
        }
        return nullptr;
    }
    if (m->hash) {
        const elf::u32 nbucket = m->hash[0];
        const auto* bucket = m->hash + 2;
        const auto* chain = bucket + nbucket;
        for (elf::u32 i = bucket[sysv_hash(name) % nbucket]; i != 0; i = chain[i])
            if (void* p = defined(i)) return p;
    }
    return nullptr;
}

okld_module* find_loaded(const char* name) {
    for (okld_module* m = g_modules; m; m = m->next) if (equal(m->name, name)) return m;
    return nullptr;
}

// A debugger object retains link relocations and describes allocated sections
// at their actual addresses. The original executable bytes stay unchanged.
bool announce(okld_module* m, const unsigned char* bytes, okld_size n, okld_why* why) {
    const okld_host* h = m->host;
    if (!h->debugger) return true;
    void* copy_ = nullptr;
    okld_size size = 0;
    if (!debugger_image(bytes, n, reinterpret_cast<elf::u64>(m->base), h, &copy_, &size, why)) return false;
    auto* entry = static_cast<jit_code_entry*>(h->alloc(sizeof(jit_code_entry), h->ctx));
    if (!entry) {
        h->free(copy_, size, h->ctx);
        say(why, "no memory for the debugger registration");
        return false;
    }
    entry->symfile_addr = reinterpret_cast<const char*>(copy_);
    entry->symfile_size = size;
    entry->prev = nullptr;
    lock();
    entry->next = __jit_debug_descriptor.first_entry;
    if (entry->next) entry->next->prev = entry;
    __jit_debug_descriptor.first_entry = entry;
    __jit_debug_descriptor.relevant_entry = entry;
    __jit_debug_descriptor.action_flag = 1;   // JIT_REGISTER_FN
    __jit_debug_register_code();
    unlock();
    m->debug_entry = entry;
    m->debug_copy = copy_;
    m->debug_size = size;
    return true;
}

void withdraw(okld_module* m) {
    if (!m->debug_entry) return;
    auto* e = static_cast<jit_code_entry*>(m->debug_entry);
    lock();
    if (e->prev) e->prev->next = e->next; else __jit_debug_descriptor.first_entry = e->next;
    if (e->next) e->next->prev = e->prev;
    __jit_debug_descriptor.relevant_entry = e;
    __jit_debug_descriptor.action_flag = 2;   // JIT_UNREGISTER_FN
    __jit_debug_register_code();
    unlock();
    m->host->free(m->debug_copy, m->debug_size, m->host->ctx);
    m->host->free(e, sizeof(jit_code_entry), m->host->ctx);
}

// Whether a relocation's symbol is one the module imports: named, and not
// defined by it.
bool imports(const okld_module* m, elf::u32 index) {
    return index != 0 && symbol_of(m, index).shndx == elf::shn_undef;
}

// EACH RELOCATION WRITES A WRITABLE SEGMENT, or the image is refused: a
// segment that is not writable may be the file's own pages (okld_host::map),
// and a write the format does not allow (SPEC 12.2: no text relocation) is
// refused rather than made wherever its offset points.
// What a load applies: every relocation (anywhere), those naming a symbol (at
// a base, whose bytes hold the relative ones), or those naming an import (a
// snapshot, whose bytes hold what the initialisers made of the rest).
enum class applying { all, named, imports };

int relocate(okld_module* m, const view& v, const okld_host* host, const writable& w, applying what, okld_why* why) {
    const bool placed = what != applying::all;
    const elf::u64 b = reinterpret_cast<elf::u64>(m->base);
    const elf::u16 machine = v.eh->machine;
    const elf::u64 wsz = v.word();
    auto put = [&](elf::u64 offset, elf::u64 value) { v.put_word(m->base + offset, value); };
    auto symbol_address = [&](elf::u32 index, bool& ok) -> elf::u64 {
        ok = true;
        if (index == 0) return 0;
        const auto s = symbol_of(m, index);
        if (s.shndx != elf::shn_undef) return s.shndx == elf::shn_abs ? s.value : b + s.value;
        const char* name = s.name < m->strsz ? m->strtab + s.name : "";
        if (void* p = host->resolve ? host->resolve(name, host->ctx) : nullptr) return reinterpret_cast<elf::u64>(p);
        for (okld_size k = 0; k < m->needed_count; ++k)
            if (void* p = lookup(m->needed[k], name)) return reinterpret_cast<elf::u64>(p);
        if (elf::st_bind(s.info) == elf::stb_weak) return 0;
        ok = false;
        say(why, "the image imports '", name, "', which neither the implementation nor an image it needs provides");
        return 0;
    };
    auto apply = [&](elf::i64 tag, elf::i64 size_tag) -> bool {
        const elf::u64 at = v.dynamic(tag, ~0ull), bytes = v.dynamic(size_tag);
        if (at == ~0ull || bytes == 0) return true;
        const unsigned char* table = m->base + at;
        for (elf::u64 k = 0; k < bytes / v.relocation_size(); ++k) {
            const elf::rela r = relocation_of(table, k, v.wide);
            const elf::u32 t = elf::r_type(r.info);
            if (t != none_type(v) && !w.holds(r.offset, wsz)) {
                say(why, "a relocation writes outside the image's writable segments (SPEC 12.2)");
                return false;
            }
            // AT ITS BASE THE RELATIVE ONES ARE ALREADY IN THE BYTES (SPEC
            // 12.3, openkal 0.23): what remains names a symbol.
            if (placed && !names_a_symbol(v, t)) continue;
            if (what == applying::imports && !imports(m, elf::r_sym(r.info))) continue;
            bool ok = true;
            const elf::u64 addend = static_cast<elf::u64>(r.addend);
            if (machine == elf::em_x86_64) {
                switch (t) {
                    case elf::r_x86_64_none: break;
                    case elf::r_x86_64_relative: put(r.offset, b + addend); break;
                    case elf::r_x86_64_64: put(r.offset, symbol_address(elf::r_sym(r.info), ok) + addend); break;
                    case elf::r_x86_64_glob_dat:
                    case elf::r_x86_64_jump_slot: put(r.offset, symbol_address(elf::r_sym(r.info), ok)); break;
                    default: say(why, "a relocation type the format does not allow (SPEC 12.2)"); return false;
                }
            } else if (machine == elf::em_386) {
                // i386 with explicit addends (-z rela): GLOB_DAT and JMP_SLOT
                // hold the symbol's address, as on x86-64.
                switch (t) {
                    case elf::r_386_none: break;
                    case elf::r_386_relative: put(r.offset, b + addend); break;
                    case elf::r_386_32: put(r.offset, symbol_address(elf::r_sym(r.info), ok) + addend); break;
                    case elf::r_386_glob_dat:
                    case elf::r_386_jmp_slot: put(r.offset, symbol_address(elf::r_sym(r.info), ok)); break;
                    default: say(why, "a relocation type the format does not allow (SPEC 12.2)"); return false;
                }
            } else {
                switch (t) {
                    case elf::r_aarch64_none: break;
                    case elf::r_aarch64_relative: put(r.offset, b + addend); break;
                    case elf::r_aarch64_abs64:
                    case elf::r_aarch64_glob_dat:
                    case elf::r_aarch64_jump_slot:
                        put(r.offset, symbol_address(elf::r_sym(r.info), ok) + addend); break;
                    default: say(why, "a relocation type the format does not allow (SPEC 12.2)"); return false;
                }
            }
            if (!ok) return false;
        }
        return true;
    };
    if (!apply(elf::dt_rela, elf::dt_relasz) || !apply(elf::dt_jmprel, elf::dt_pltrelsz)) return -1;
    // DT_RELR: packed relative relocations, already in the bytes of an image
    // at its base.
    if (const elf::u64 at = v.dynamic(elf::dt_relr, ~0ull); !placed && at != ~0ull) {
        const elf::u64 bytes = v.dynamic(elf::dt_relrsz);
        const unsigned char* e = m->base + at;
        elf::u64 next = 0;   // the offset the first bit of a bitmap entry names
        bool ok = true;
        auto add = [&](elf::u64 offset) {
            ok = w.holds(offset, wsz);
            if (ok) put(offset, v.word_of(m->base + offset) + b);
        };
        // An entry is a word of the class: an address, or a bitmap of the
        // word's width less one.
        for (elf::u64 k = 0; ok && k < bytes / wsz; ++k) {
            const elf::u64 entry = v.word_of(e + k * wsz);
            if ((entry & 1) == 0) {
                add(entry);
                next = entry + wsz;
            } else {
                elf::u64 bits = entry >> 1;
                for (elf::u64 i = 0; ok && bits; ++i, bits >>= 1)
                    if (bits & 1) add(next + wsz * i);
                next += (wsz * 8 - 1) * wsz;
            }
        }
        if (!ok) {
            say(why, "a relocation writes outside the image's writable segments (SPEC 12.2)");
            return -1;
        }
    }
    return 0;
}

}  // namespace

namespace {
// A placed module's region, its own program headers and its record.
void discard(okld_module* m) {
    const okld_host* host = m->host;
    if (m->own_phdr) host->free(m->own_phdr, static_cast<okld_size>(m->phentsize) * m->phnum, host->ctx);
    host->release(m->base, m->span, host->ctx);
    host->free(m, sizeof *m, host->ctx);
}
}  // namespace

namespace {
// WHERE AN IMAGE'S DATA COMES FROM WHEN IT IS AT A BASE: blocks of bytes that
// are, at their addresses, what its writable segments hold --- the stored
// segments of its placement (SPEC 12.4, type 3), in its own file, or a
// loader's prepared copy (type 5), a file of its own --- and, for a snapshot,
// the memory its initialisers obtained.
struct source {
    const unsigned char* bytes = nullptr;   // the file the blocks are in
    size                 n = 0;
    elf::u64             base = 0;
    okld_prepared_block  block[OKLD_PREPARED_MAX];
    elf::u32             count = 0;
    bool                 snapshot = false;
    elf::u64             arena = 0, arena_size = 0;
};

// The 64 KiB blocks of a writable segment a relocation naming a symbol writes:
// they are written on every start, so they are not a file's read-only pages.
struct named_blocks {
    elf::u64 first = 0;
    bool     named[1024] = {};
    elf::u64 count = 0;
};

constexpr elf::u64 block_size = 65536;

void mark_named(const view& v, elf::u64 from, elf::u64 to, named_blocks& out) {
    out.first = round_down(from, block_size);
    out.count = (round_up(to, block_size) - out.first) / block_size;
    if (out.count > 1024) out.count = 1024;
    auto mark = [&](elf::i64 tag, elf::i64 size_tag) {
        const auto n = v.relocation_count(tag, size_tag);
        const elf::u64 w = v.word();
        for (size k = 0; k < n; ++k) {
            const auto r = v.relocation(tag, k);
            if (!names_a_symbol(v, elf::r_type(r.info))) continue;
            const elf::u64 o = r.offset;
            if (o + w <= from || o >= to) continue;
            const elf::u64 a = (o > out.first ? o - out.first : 0) / block_size;
            const elf::u64 b = (o + w - 1 - out.first) / block_size;
            if (a < out.count) out.named[a] = true;
            if (b < out.count) out.named[b] = true;
        }
    };
    mark(elf::dt_rela, elf::dt_relasz);
    mark(elf::dt_jmprel, elf::dt_pltrelsz);
}

// A block's bytes into the region at `region', which begins at `at' (the
// image's base, or a snapshot's arena) and holds `span' bytes: each 64 KiB of
// it the block covers whole is the file's pages where the host can make it so
// --- written privately, or read only where it lies in the read-only-after-
// relocation range and no relocation naming a symbol writes it --- and the rest
// is copied. A run of blocks alike is one request.
void place_block(const okld_host* host, unsigned char* region, elf::u64 at, elf::u64 span,
                 const source& src, const okld_prepared_block& b, elf::u64 relro_from, elf::u64 relro_to,
                 const named_blocks& named) {
    const elf::u64 lo = b.address - at, hi = lo + b.size;   // in the region
    const elf::u64 g = host->granularity(host->ctx);
    auto how_of = [&](elf::u64 chunk) -> int {
        const elf::u64 image_lo = chunk + at - src.base;   // as an address of the image
        const bool relro = image_lo >= relro_from && image_lo + block_size <= relro_to;
        const elf::u64 k = (image_lo - named.first) / block_size;
        const bool written = image_lo < named.first || k >= named.count || named.named[k];
        return relro && !written ? 0 : OKLD_MAP_WRITE;
    };
    elf::u64 c = round_up(lo, block_size);
    // The head before the first whole block, copied.
    const elf::u64 head_end = c < hi ? c : hi;
    if (head_end > lo) copy(region + lo, src.bytes + b.offset, head_end - lo);
    while (c < hi) {
        const elf::u64 room = hi - c;
        // The tail of the block: whole to the granularity where it ends the
        // span's writable part, copied otherwise.
        elf::u64 len = room >= block_size ? block_size : 0;
        if (len == 0) {
            const elf::u64 rounded = round_up(room, g);
            len = c + rounded <= span ? rounded : 0;
        }
        bool mapped = false;
        if (len != 0 && host->map) {
            const int how = how_of(c);
            elf::u64 run = len;
            while (run % block_size == 0 && c + run + block_size <= hi && how_of(c + run) == how) run += block_size;
            if (c + run < hi && hi - (c + run) < block_size) {
                const elf::u64 tail = round_up(hi - (c + run), g);
                if (c + run + tail <= span && how_of(c + run) == how) run += tail;
            }
            // The data an image at a base starts with, read in with it where
            // the host reads everything ahead; a snapshot's is read as it is
            // touched (a start touches little of what its initialisers made).
            const int ahead = host->prefetch >= 2 && !src.snapshot ? OKLD_MAP_PREFETCH : 0;
            if (host->map(region, c, run, src.bytes, b.offset + (c - lo), how | ahead, host->ctx) == 0) {
                mapped = true;
                c += run;
            }
        }
        if (!mapped) {
            const elf::u64 n = room < block_size ? room : block_size;
            copy(region + c, src.bytes + b.offset + (c - lo), n);
            c += n;
        }
    }
}

// The pages an image states it touches when it starts (SPEC 12.4, type 4), as
// a set of the 64 KiB blocks of its file.
struct touched {
    okld_u32 ranges[2 * OKLD_TOUCH_MAX];
    okld_u32 count = 0;
    bool holds(elf::u64 file_block) const {
        for (okld_u32 i = 0; i < count; ++i)
            if (file_block >= ranges[2 * i] && file_block < static_cast<elf::u64>(ranges[2 * i]) + ranges[2 * i + 1])
                return true;
        return false;
    }
};

// A declined run is copied alone: earlier runs may already be read-only
// file mappings. Recopying the segment after a later refusal writes those
// pages (for example, when Windows refuses a final run below 64 KiB).
int map_or_copy(const okld_host* host, unsigned char* region, elf::u64 lo, elf::u64 hi,
                const void* bytes, elf::u64 from, int how) {
    if (host->map(region, lo, hi - lo, bytes, from, how, host->ctx) == 0) return 0;
    copy(region + lo, static_cast<const unsigned char*>(bytes) + from, hi - lo);
    if (how & OKLD_MAP_EXECUTE) {
        if (host->publish(region, lo, hi - lo, host->ctx) != 0) return -1;
        sync_instructions(region + lo, region + hi);
    }
    return 0;
}

// A segment that is the file's pages: in runs that are read in now and runs
// that are not, where the image states its touches and the host reads ahead.
// Runs a few blocks apart are joined: a request costs more than the pages.
int map_segment(const okld_host* host, unsigned char* region, elf::u64 lo, elf::u64 hi, const void* bytes,
                elf::u64 from, int how, const touched* t) {
    if (!t || t->count == 0) return map_or_copy(host, region, lo, hi, bytes, from, how);
    const elf::u64 blocks = (hi - lo + block_size - 1) / block_size;
    auto is_touched = [&](elf::u64 k) { return t->holds((from + k * block_size) / block_size); };
    elf::u64 k = 0;
    while (k < blocks) {
        const bool on = is_touched(k);
        elf::u64 e = k + 1;
        for (;;) {
            while (e < blocks && is_touched(e) == on) ++e;
            // A gap of at most two blocks inside a run read in is read in too.
            if (on && e < blocks) {
                elf::u64 g2 = e;
                while (g2 < blocks && !is_touched(g2) && g2 - e < 3) ++g2;
                if (g2 < blocks && g2 - e < 3 && is_touched(g2)) { e = g2; continue; }
            }
            break;
        }
        const elf::u64 a = lo + k * block_size, z = e == blocks ? hi : lo + e * block_size;
        if (map_or_copy(host, region, a, z, bytes, from + k * block_size, how | (on ? OKLD_MAP_PREFETCH : 0)) != 0)
            return -1;
        k = e;
    }
    return 0;
}

// The placement an image states, as a source in its own file.
bool placement_source(const view& v, const placement& p, const void* bytes, source& out) {
    out.bytes = static_cast<const unsigned char*>(bytes);
    out.n = v.len;
    out.base = p.base;
    out.count = 0;
    for (elf::u32 i = 0; i < p.count && out.count < OKLD_PREPARED_MAX; ++i)
        out.block[out.count++] = okld_prepared_block{ p.base + p.e[i].vaddr, p.e[i].offset, p.e[i].size };
    return true;
}
}  // namespace

namespace {
int load_image(const void* bytes, okld_size n, const char* name, const okld_host* host, const source* prepared,
               okld_module** out, okld_why* why);
}  // namespace

namespace {
int load_image(const void* bytes, okld_size n, const char* name, const okld_host* host, const source* prepared,
               okld_module** out, okld_why* why) {
    view v;
    if (!open(bytes, n, v, why ? why->text : nullptr, why ? sizeof why->text : 0)) return -1;
    if (char reason[256]; okld_check(bytes, n, nullptr, [](const char*, void*) { return 1; },
                                     [](const char* s, void* c) { auto* r = static_cast<char*>(c); if (!*r) copy(r, s, length(s) + 1 > 256 ? 255 : length(s) + 1); },
                                     (reason[0] = 0, reason)) > 0) {
        say(why, "the image does not follow the format: ", reason);
        return -1;
    }
    lock();
    if (okld_module* existing = name ? find_loaded(name) : nullptr) { ++existing->references; unlock(); *out = existing; return 0; }
    unlock();

    auto* m = static_cast<okld_module*>(host->alloc(sizeof(okld_module), host->ctx));
    if (!m) { say(why, "no memory for the loader's record"); return -1; }
    fill(m, 0, sizeof *m);
    m->host = host;
    m->references = 1;
    if (name) copy(m->name, name, length(name) < 255 ? length(name) : 255);

    // What the image needs, first: each is loaded by name through the host.
    size dn = 0;
    const auto* dyn = v.dynamic_table(dn);
    for (size k = 0; dyn && k < dn && dyn[k].tag != elf::dt_null; ++k) {
        if (dyn[k].tag != elf::dt_needed) continue;
        const char* need = v.string(dyn[k].val);
        if (!need) continue;
        if (prepared && prepared->snapshot) {
            say(why, "a snapshot of an image that needs '", need, "' is refused: that image would start without its own");
            host->free(m, sizeof *m, host->ctx);
            return -1;
        }
        if (m->needed_count == 16) { say(why, "the image needs more than sixteen images"); host->free(m, sizeof *m, host->ctx); return -1; }
        okld_size nsize = 0;
        const void* nbytes = host->find_needed ? host->find_needed(need, &nsize, host->ctx) : nullptr;
        if (!nbytes) { say(why, "the image needs '", need, "', which is not found"); host->free(m, sizeof *m, host->ctx); return -1; }
        okld_module* nm = nullptr;
        const int rc = load_image(nbytes, nsize, need, host, nullptr, &nm, why);
        if (host->release_bytes) host->release_bytes(nbytes, nsize, host->ctx);
        if (rc != 0) { host->free(m, sizeof *m, host->ctx); return rc; }
        m->needed[m->needed_count++] = nm;
    }

    // The span, reserved once: the image's parts lie at fixed distances.
    const okld_size g = host->granularity(host->ctx);
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (v.ph[k].type == elf::pt_load && v.ph[k].vaddr + v.ph[k].memsz > m->span) m->span = v.ph[k].vaddr + v.ph[k].memsz;
    m->span = round_up(m->span, g);
    // AT ITS BASE WHERE THE IMAGE STATES ONE AND THE HOST CAN PLACE IT THERE
    // (SPEC 12.3, openkal 0.23): its writable segments are then the bytes it
    // stores for that base, and no relative relocation is applied. A prepared
    // copy (type 5, 0.4) brings a base of its own and the data for it, and is
    // refused rather than placed elsewhere: the bytes are for that base alone.
    // Otherwise anywhere, and every relocation is.
    placement placed_at;
    source own;
    const source* src = nullptr;
    if (prepared) {
        if (!host->reserve_at || prepared->base % g != 0) {
            say(why, "the prepared copy's base cannot be reserved here");
            host->free(m, sizeof *m, host->ctx);
            return -1;
        }
        m->base = static_cast<unsigned char*>(host->reserve_at(reinterpret_cast<void*>(prepared->base), m->span, host->ctx));
        if (!m->base) { say(why, "the prepared copy's base is not free"); host->free(m, sizeof *m, host->ctx); return -1; }
        src = prepared;
    } else if (host->reserve_at && read_placement(v, placed_at) && placed_at.base % g == 0) {
        m->base = static_cast<unsigned char*>(host->reserve_at(reinterpret_cast<void*>(placed_at.base), m->span, host->ctx));
        if (m->base) { placement_source(v, placed_at, bytes, own); src = &own; }
    }
    const bool placed = src != nullptr;
    if (!placed) m->base = static_cast<unsigned char*>(host->reserve(m->span, host->ctx));
    if (!m->base) { say(why, "the address space for the image could not be reserved"); host->free(m, sizeof *m, host->ctx); return -1; }
    // A SNAPSHOT'S ARENA, after the span: the memory its initialisers obtained,
    // at the addresses they were given.
    unsigned char* arena = nullptr;
    if (placed && src->snapshot && src->arena_size != 0) {
        arena = static_cast<unsigned char*>(host->reserve_at(reinterpret_cast<void*>(src->arena), src->arena_size, host->ctx));
        if (!arena) {
            say(why, "the snapshot's arena is not free");
            host->release(m->base, m->span, host->ctx);
            host->free(m, sizeof *m, host->ctx);
            return -1;
        }
    }
    touched t;
    if (host->prefetch) t.count = okld_touches(bytes, n, t.ranges, OKLD_TOUCH_MAX);
    // Each segment is its file bytes and then zeros to its size in memory: the
    // region is zero when it is returned (openkal 0.23), so the zeros are not
    // written and a page of them is resident only once the program touches it.
    // What lies between segments is no segment's and is not written either.
    //
    // A SEGMENT NOTHING WRITES IS THE FILE'S OWN PAGES where the host can make
    // it so (0.3, openkal 0.21): instructions and read-only data are the file's
    // bytes unchanged, and a copy of them made each program that started write
    // and hold the whole of them --- 54 MB and 14 000 page faults before the
    // first instruction of a language server, where a program of the
    // environment pays for the pages it touches. Mapped from the alignment
    // below the segment to the granule above its end, which no other segment
    // shares; otherwise, and where the host declines, copied.
    bool mapped[32] = {};
    writable w;
    // The read-only-after-relocation range, whose pages an image at its base
    // need not write: those no symbol relocation writes are the file's.
    elf::u64 relro_from = 0, relro_to = 0;
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (v.ph[k].type == elf::pt_gnu_relro) { relro_from = v.ph[k].vaddr; relro_to = v.ph[k].vaddr + v.ph[k].memsz; }
    for (unsigned k = 0; k < v.eh->phnum; ++k) {
        const auto& p = v.ph[k];
        if (p.type != elf::pt_load) continue;
        if (p.offset + p.filesz > n) { say(why, "a segment extends beyond the file"); host->release(m->base, m->span, host->ctx); host->free(m, sizeof *m, host->ctx); return -1; }
        if (p.filesz > p.memsz) { say(why, "a segment holds more of the file than its size in memory"); host->release(m->base, m->span, host->ctx); host->free(m, sizeof *m, host->ctx); return -1; }
        if (p.flags & elf::pf_w) {
            if (w.count == 8) { say(why, "the image has more than eight writable segments"); host->release(m->base, m->span, host->ctx); host->free(m, sizeof *m, host->ctx); return -1; }
            w.from[w.count] = p.vaddr; w.to[w.count] = p.vaddr + p.memsz; ++w.count;
            // AT A BASE THE DATA IS THE SOURCE'S (below), not the file's bytes.
            if (placed) continue;
        } else if (host->map && k < 32 && p.filesz == p.memsz && p.filesz != 0
                   && p.vaddr % file_alignment == p.offset % file_alignment) {
            const elf::u64 lo = round_down(p.vaddr, file_alignment), hi = round_up(p.vaddr + p.filesz, g);
            const elf::u64 from = p.offset - (p.vaddr - lo);
            bool alone = from + (hi - lo) <= n;
            for (unsigned j = 0; alone && j < v.eh->phnum; ++j) {
                const auto& q = v.ph[j];
                if (j == k || q.type != elf::pt_load) continue;
                const elf::u64 qlo = round_down(q.vaddr, g), qhi = round_up(q.vaddr + q.memsz, g);
                if (qlo < hi && lo < qhi) alone = false;
            }
            if (alone) {
                if (map_segment(host, m->base, lo, hi, bytes, from, (p.flags & elf::pf_x) ? OKLD_MAP_EXECUTE : 0,
                                host->prefetch ? &t : nullptr) != 0) {
                    say(why, "the environment refused to make a copied run of the image's instructions executable");
                    host->release(m->base, m->span, host->ctx);
                    host->free(m, sizeof *m, host->ctx);
                    return -1;
                }
                mapped[k] = true;
                continue;
            }
        }
        copy(m->base + p.vaddr, static_cast<const unsigned char*>(bytes) + p.offset, p.filesz);
    }
    // THE DATA OF AN IMAGE AT A BASE (0.4): each block of the source at its
    // address, the file's pages written privately where the host can make them
    // so (openkal 0.23, KAL_EXEC_MAP_WRITE) --- shared until the program writes
    // a page, as a program of the environment's data is --- and copied where it
    // cannot. A snapshot's blocks are the whole of the data and of the arena.
    if (placed) {
        // The blocks a relocation naming a symbol writes, over the writable
        // segments together: those are not a file's read-only pages.
        named_blocks named;
        elf::u64 wlo = ~0ull, whi = 0;
        for (elf::u32 k = 0; k < w.count; ++k) {
            if (w.from[k] < wlo) wlo = w.from[k];
            if (w.to[k] > whi) whi = w.to[k];
        }
        if (w.count) mark_named(v, wlo, whi, named);
        for (elf::u32 i = 0; i < src->count; ++i) {
            const okld_prepared_block& b = src->block[i];
            const bool in_arena = arena && b.address >= src->arena && b.address - src->arena < src->arena_size;
            if (in_arena) {
                if (b.size > src->arena_size - (b.address - src->arena)) continue;
                place_block(host, arena, src->arena, src->arena_size, *src, b, 0, 0, named);
            } else {
                const elf::u64 at = b.address - src->base;
                if (b.address < src->base || !w.holds(at, b.size)) {
                    say(why, "a block of the prepared data lies outside the image's writable segments");
                    if (arena) host->release(arena, src->arena_size, host->ctx);
                    host->release(m->base, m->span, host->ctx);
                    host->free(m, sizeof *m, host->ctx);
                    return -1;
                }
                place_block(host, m->base, src->base, m->span, *src, b, relro_from, relro_to, named);
            }
        }
    }
    m->entry = v.eh->entry;
    m->phnum = v.eh->phnum;
    m->phentsize = v.eh->phentsize;
    const elf::u64 phbytes = static_cast<elf::u64>(m->phentsize) * m->phnum;
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (v.ph[k].type == elf::pt_load && v.eh->phoff >= v.ph[k].offset && v.eh->phoff + phbytes <= v.ph[k].offset + v.ph[k].filesz)
            m->phdr = m->base + v.ph[k].vaddr + (v.eh->phoff - v.ph[k].offset);
    // THE LOADER KEEPS NO POINTER INTO THE CALLER'S BYTES, which the caller may
    // release once the image is loaded: program headers no segment holds are
    // copied into the record, as the image states them.
    if (!m->phdr) {
        m->own_phdr = static_cast<unsigned char*>(host->alloc(phbytes, host->ctx));
        if (!m->own_phdr) { say(why, "no memory for the image's program headers"); host->release(m->base, m->span, host->ctx); host->free(m, sizeof *m, host->ctx); return -1; }
        copy(m->own_phdr, v.data + v.eh->phoff, phbytes);
        m->phdr = m->own_phdr;
    }

    m->wide = v.wide;
    m->symtab = m->base + v.dynamic(elf::dt_symtab);
    m->strtab = reinterpret_cast<const char*>(m->base + v.dynamic(elf::dt_strtab));
    m->strsz = v.dynamic(elf::dt_strsz);
    if (const elf::u64 h = v.dynamic(elf::dt_hash, ~0ull); h != ~0ull) m->hash = reinterpret_cast<const elf::u32*>(m->base + h);
    if (const elf::u64 h = v.dynamic(elf::dt_gnu_hash, ~0ull); h != ~0ull) m->gnu_hash = reinterpret_cast<const elf::u32*>(m->base + h);
    m->init = v.dynamic(elf::dt_init); m->fini = v.dynamic(elf::dt_fini);
    m->init_array = v.dynamic(elf::dt_init_array); m->init_arraysz = v.dynamic(elf::dt_init_arraysz);
    m->fini_array = v.dynamic(elf::dt_fini_array); m->fini_arraysz = v.dynamic(elf::dt_fini_arraysz);
    m->rela = v.dynamic(elf::dt_rela, ~0ull); m->relasz = v.dynamic(elf::dt_relasz);
    m->jmprel = v.dynamic(elf::dt_jmprel, ~0ull); m->pltrelsz = v.dynamic(elf::dt_pltrelsz);
    m->machine = v.eh->machine;

    const applying what = !placed ? applying::all : src->snapshot ? applying::imports : applying::named;
    if (relocate(m, v, host, w, what, why) != 0) { discard(m); return -1; }

    // READ-ONLY AFTER RELOCATION (openkal 0.23): the addresses of functions and
    // data relocation wrote, made read-only now, as a program of the
    // environment's are by its loader --- for good where the image is never
    // unloaded. The whole pages of the range: its first and last may share a
    // page with data that is written.
    if (host->seal && relro_to > relro_from) {
        const elf::u64 lo = round_up(relro_from, g), hi = round_down(relro_to, g);
        if (hi > lo) host->seal(m->base, lo, hi - lo, host->permanent, host->ctx);
    }
    // A SNAPSHOT'S INITIALISERS HAVE RUN: what they made is its data.
    if (placed && src->snapshot) m->initialised = true;

    // Publish what executes and was copied; the rest stays writable. A segment
    // that is the file's pages is executable already, and its bytes reached
    // memory through the environment rather than through this loader's data
    // path, so its instructions need no maintenance here either.
    for (unsigned k = 0; k < v.eh->phnum; ++k) {
        const auto& p = v.ph[k];
        if (p.type != elf::pt_load || !(p.flags & elf::pf_x) || (k < 32 && mapped[k])) continue;
        const elf::u64 from = round_down(p.vaddr, g), to = round_up(p.vaddr + p.memsz, g);
        if (host->publish(m->base, from, to - from, host->ctx) != 0) {
            say(why, "the environment refused to make the image's instructions executable");
            discard(m);
            return -1;
        }
        sync_instructions(m->base + p.vaddr, m->base + p.vaddr + p.memsz);
    }

    if (!announce(m, static_cast<const unsigned char*>(bytes), n, why)) {
        for (okld_size k = m->needed_count; k > 0; --k) okld_unload(m->needed[k - 1]);
        discard(m);
        return -1;
    }
    lock();
    m->next = g_modules;
    g_modules = m;
    unlock();
    *out = m;
    return 0;
}
}  // namespace

extern "C" int okld_load(const void* bytes, okld_size n, const char* name, const okld_host* host,
                         okld_module** out, okld_why* why) {
    return load_image(bytes, n, name, host, nullptr, out, why);
}

extern "C" int okld_load_prepared(const void* bytes, okld_size n, const char* name, const okld_host* host,
                                  const void* prepared, okld_size prepared_size, okld_module** out, okld_why* why) {
    okld_prepared_info info{};
    source src;
    if (okld_prepared(prepared, prepared_size, &info, src.block, OKLD_PREPARED_MAX) != 0
        || info.count > OKLD_PREPARED_MAX) {
        say(why, "not a prepared copy of an image (SPEC 12.4, type 5)");
        return -1;
    }
    src.bytes = static_cast<const unsigned char*>(prepared);
    src.n = prepared_size;
    src.base = info.base;
    src.count = info.count;
    src.snapshot = (info.flags & OKLD_PREPARED_SNAPSHOT) != 0;
    src.arena = info.arena;
    src.arena_size = info.arena_size;
    for (elf::u32 i = 0; i < src.count; ++i)
        if (src.block[i].offset > prepared_size || src.block[i].size > prepared_size - src.block[i].offset) {
            say(why, "a block of the prepared copy lies beyond its file");
            return -1;
        }
    return load_image(bytes, n, name, host, &src, out, why);
}

namespace {
void run_init(okld_module* m, void (*call)(void*, void*), void* ctx) {
    if (m->initialised) return;
    m->initialised = true;
    for (okld_size k = 0; k < m->needed_count; ++k) run_init(m->needed[k], call, ctx);
    if (m->init) call(m->base + m->init, ctx);
    const auto* arr = reinterpret_cast<void* const*>(m->base + m->init_array);
    for (elf::u64 k = 0; m->init_array && k < m->init_arraysz / sizeof(void*); ++k)
        if (arr[k] && arr[k] != reinterpret_cast<void*>(~0ull)) call(arr[k], ctx);
}
void run_fini(okld_module* m, void (*call)(void*, void*), void* ctx) {
    if (m->finalised || !m->initialised) return;
    m->finalised = true;
    const auto* arr = reinterpret_cast<void* const*>(m->base + m->fini_array);
    for (elf::u64 k = m->fini_array ? m->fini_arraysz / sizeof(void*) : 0; k > 0; --k)
        if (arr[k - 1] && arr[k - 1] != reinterpret_cast<void*>(~0ull)) call(arr[k - 1], ctx);
    if (m->fini) call(m->base + m->fini, ctx);
    for (okld_size k = m->needed_count; k > 0; --k) run_fini(m->needed[k - 1], call, ctx);
}
}  // namespace

extern "C" int okld_bound_imports(okld_module* m, int (*each)(void*, okld_u64, const char*, void*), void* ctx) {
    if (!m || !each) return 0;
    const okld_host* host = m->host;
    const elf::u64 tables[2][2] = { { m->rela, m->relasz }, { m->jmprel, m->pltrelsz } };
    for (const auto& t : tables) {
        if (t[0] == ~0ull) continue;
        const unsigned char* table = m->base + t[0];
        const elf::u64 entry = m->wide ? sizeof(elf::rela) : sizeof(elf::rela32);
        for (elf::u64 k = 0; k < t[1] / entry; ++k) {
            const elf::rela r = relocation_of(table, k, m->wide);
            const elf::u32 index = elf::r_sym(r.info);
            if (!imports(m, index)) continue;
            const auto sym = symbol_of(m, index);
            const char* name = sym.name < m->strsz ? m->strtab + sym.name : "";
            elf::u64 value = 0;
            if (void* p = host->resolve ? host->resolve(name, host->ctx) : nullptr) value = reinterpret_cast<elf::u64>(p);
            for (okld_size n = 0; value == 0 && n < m->needed_count; ++n)
                if (void* p = lookup(m->needed[n], name)) value = reinterpret_cast<elf::u64>(p);
            // The addend counts where the relocation adds it: every type but
            // GLOB_DAT and JUMP_SLOT of x86-64 and of i386.
            const elf::u32 type = elf::r_type(r.info);
            const bool adds = m->machine == elf::em_x86_64 ? type != elf::r_x86_64_glob_dat && type != elf::r_x86_64_jump_slot
                            : m->machine == elf::em_386    ? type != elf::r_386_glob_dat && type != elf::r_386_jmp_slot
                                                           : true;
            if (value != 0 && adds) value += static_cast<elf::u64>(r.addend);
            if (const int stop = each(m->base + r.offset, value, name, ctx)) return stop;
        }
    }
    return 0;
}

extern "C" void okld_initialise(okld_module* m, void (*call)(void*, void*), void* ctx) { run_init(m, call, ctx); }
extern "C" void okld_finalise(okld_module* m, void (*call)(void*, void*), void* ctx) { run_fini(m, call, ctx); }
extern "C" void* okld_symbol(okld_module* m, const char* name) { return lookup(m, name); }
extern "C" void* okld_entry(okld_module* m) { return m->entry ? m->base + m->entry : nullptr; }
extern "C" void* okld_base(okld_module* m) { return m->base; }
extern "C" const char* okld_name(okld_module* m) { return m->name; }

extern "C" void okld_unload(okld_module* m) {
    if (!m) return;
    lock();
    if (--m->references > 0) { unlock(); return; }
    for (okld_module** p = &g_modules; *p; p = &(*p)->next) if (*p == m) { *p = m->next; break; }
    unlock();
    withdraw(m);
    for (okld_size k = 0; k < m->needed_count; ++k) okld_unload(m->needed[k]);
    discard(m);
}

extern "C" int okld_iterate(int (*each)(void*, const void*, okld_u32, const char*, void*), void* ctx) {
    lock();
    okld_module* list[64];
    int count = 0;
    for (okld_module* m = g_modules; m && count < 64; m = m->next) list[count++] = m;
    unlock();
    for (int i = 0; i < count; ++i)
        if (const int r = each(list[i]->base, list[i]->phdr, list[i]->phnum, list[i]->name, ctx)) return r;
    return 0;
}

extern "C" okld_module* okld_containing(const void* address) {
    const auto* a = static_cast<const unsigned char*>(address);
    lock();
    okld_module* found = nullptr;
    for (okld_module* m = g_modules; m; m = m->next) if (a >= m->base && a < m->base + m->span) { found = m; break; }
    unlock();
    return found;
}
