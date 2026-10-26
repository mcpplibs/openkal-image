// Loading an image (SPEC clause 12.3): map, relocate, bind, publish; and the
// record of what is loaded, for `dl_iterate_phdr', `dladdr' and a debugger.
#include <okld.h>
#include "image.h"

namespace {

using namespace okld;

struct okld_module_rec;

}  // namespace

struct okld_module {
    okld_module*      next = nullptr;         // every loaded module
    const okld_host*  host = nullptr;
    unsigned char*    base = nullptr;
    elf::u64          span = 0;
    const elf::phdr*  phdr = nullptr;         // within the mapped image
    elf::u32          phnum = 0;
    elf::u64          entry = 0;
    char              name[256] = {};
    okld_module*      needed[16] = {};
    okld_size         needed_count = 0;
    int               references = 1;
    bool              initialised = false;
    bool              finalised = false;
    // Within the mapped image, from its dynamic table.
    const elf::sym*   symtab = nullptr;
    const char*       strtab = nullptr;
    elf::u64          strsz = 0;
    const elf::u32*   hash = nullptr;         // DT_HASH
    const elf::u32*   gnu_hash = nullptr;     // DT_GNU_HASH
    elf::u64          init = 0, fini = 0, init_array = 0, init_arraysz = 0, fini_array = 0, fini_arraysz = 0;
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

// An exported name of a module: defined, not local.
void* lookup(const okld_module* m, const char* name) {
    auto defined = [&](elf::u32 index) -> void* {
        const auto& s = m->symtab[index];
        if (s.shndx == elf::shn_undef || elf::st_bind(s.info) == elf::stb_local || !s.name) return nullptr;
        if (s.name >= m->strsz || !equal(m->strtab + s.name, name)) return nullptr;
        return s.shndx == elf::shn_abs ? reinterpret_cast<void*>(s.value) : m->base + s.value;
    };
    if (m->gnu_hash) {
        const elf::u32 nbuckets = m->gnu_hash[0], symoffset = m->gnu_hash[1], bloom = m->gnu_hash[2];
        const auto* buckets = m->gnu_hash + 4 + bloom * 2;
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

// The relocated copy a debugger reads: the image's bytes with every address
// moved to where the image is.
void announce(okld_module* m, const unsigned char* bytes, okld_size n) {
    const okld_host* h = m->host;
    if (!h->debugger || !h->alloc) return;
    auto* copy_ = static_cast<unsigned char*>(h->alloc(n, h->ctx));
    auto* entry = static_cast<jit_code_entry*>(h->alloc(sizeof(jit_code_entry), h->ctx));
    if (!copy_ || !entry) return;
    copy(copy_, bytes, n);
    const elf::u64 b = reinterpret_cast<elf::u64>(m->base);
    auto* eh = reinterpret_cast<elf::ehdr*>(copy_);
    eh->entry += b;
    auto* ph = reinterpret_cast<elf::phdr*>(copy_ + eh->phoff);
    for (unsigned i = 0; i < eh->phnum; ++i) { ph[i].vaddr += b; ph[i].paddr += b; }
    if (eh->shoff && eh->shoff + static_cast<elf::u64>(eh->shnum) * sizeof(elf::shdr) <= n) {
        auto* sh = reinterpret_cast<elf::shdr*>(copy_ + eh->shoff);
        for (unsigned i = 0; i < eh->shnum; ++i) {
            if (sh[i].flags & 2 /* SHF_ALLOC */) sh[i].addr += b;
            if ((sh[i].type == elf::sht_symtab || sh[i].type == elf::sht_dynsym) && sh[i].offset + sh[i].size <= n) {
                auto* sym = reinterpret_cast<elf::sym*>(copy_ + sh[i].offset);
                for (elf::u64 k = 0; k < sh[i].size / sizeof(elf::sym); ++k)
                    if (sym[k].shndx != elf::shn_undef && sym[k].shndx != elf::shn_abs && sym[k].shndx < 0xff00) sym[k].value += b;
            }
        }
    }
    entry->symfile_addr = reinterpret_cast<const char*>(copy_);
    entry->symfile_size = n;
    entry->prev = nullptr;
    entry->next = __jit_debug_descriptor.first_entry;
    if (entry->next) entry->next->prev = entry;
    __jit_debug_descriptor.first_entry = entry;
    __jit_debug_descriptor.relevant_entry = entry;
    __jit_debug_descriptor.action_flag = 1;   // JIT_REGISTER_FN
    __jit_debug_register_code();
    m->debug_entry = entry;
    m->debug_copy = copy_;
    m->debug_size = n;
}

void withdraw(okld_module* m) {
    if (!m->debug_entry) return;
    auto* e = static_cast<jit_code_entry*>(m->debug_entry);
    if (e->prev) e->prev->next = e->next; else __jit_debug_descriptor.first_entry = e->next;
    if (e->next) e->next->prev = e->prev;
    __jit_debug_descriptor.relevant_entry = e;
    __jit_debug_descriptor.action_flag = 2;   // JIT_UNREGISTER_FN
    __jit_debug_register_code();
    m->host->free(m->debug_copy, m->debug_size, m->host->ctx);
    m->host->free(e, sizeof(jit_code_entry), m->host->ctx);
}

int relocate(okld_module* m, const view& v, const okld_host* host, okld_why* why) {
    const elf::u64 b = reinterpret_cast<elf::u64>(m->base);
    const bool x86 = v.eh->machine == elf::em_x86_64;
    auto symbol_address = [&](elf::u32 index, bool& ok) -> elf::u64 {
        ok = true;
        if (index == 0) return 0;
        const auto& s = m->symtab[index];
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
        const auto* r = reinterpret_cast<const elf::rela*>(m->base + at);
        for (elf::u64 k = 0; k < bytes / sizeof(elf::rela); ++k) {
            auto* where = reinterpret_cast<elf::u64*>(m->base + r[k].offset);
            const elf::u32 t = elf::r_type(r[k].info);
            bool ok = true;
            if (x86) {
                switch (t) {
                    case elf::r_x86_64_none: break;
                    case elf::r_x86_64_relative: *where = b + static_cast<elf::u64>(r[k].addend); break;
                    case elf::r_x86_64_64: *where = symbol_address(elf::r_sym(r[k].info), ok) + static_cast<elf::u64>(r[k].addend); break;
                    case elf::r_x86_64_glob_dat:
                    case elf::r_x86_64_jump_slot: *where = symbol_address(elf::r_sym(r[k].info), ok); break;
                    default: say(why, "a relocation type the format does not allow (SPEC 12.2)"); return false;
                }
            } else {
                switch (t) {
                    case elf::r_aarch64_none: break;
                    case elf::r_aarch64_relative: *where = b + static_cast<elf::u64>(r[k].addend); break;
                    case elf::r_aarch64_abs64:
                    case elf::r_aarch64_glob_dat:
                    case elf::r_aarch64_jump_slot:
                        *where = symbol_address(elf::r_sym(r[k].info), ok) + static_cast<elf::u64>(r[k].addend); break;
                    default: say(why, "a relocation type the format does not allow (SPEC 12.2)"); return false;
                }
            }
            if (!ok) return false;
        }
        return true;
    };
    if (!apply(elf::dt_rela, elf::dt_relasz) || !apply(elf::dt_jmprel, elf::dt_pltrelsz)) return -1;
    // DT_RELR: packed relative relocations.
    if (const elf::u64 at = v.dynamic(elf::dt_relr, ~0ull); at != ~0ull) {
        const elf::u64 bytes = v.dynamic(elf::dt_relrsz);
        const auto* e = reinterpret_cast<const elf::u64*>(m->base + at);
        elf::u64* where = nullptr;
        for (elf::u64 k = 0; k < bytes / 8; ++k) {
            if ((e[k] & 1) == 0) {
                where = reinterpret_cast<elf::u64*>(m->base + e[k]);
                *where++ += b;
            } else {
                elf::u64 bits = e[k] >> 1;
                for (int i = 0; bits; ++i, bits >>= 1) if (bits & 1) where[i] += b;
                where += 63;
            }
        }
    }
    return 0;
}

}  // namespace

extern "C" int okld_load(const void* bytes, okld_size n, const char* name, const okld_host* host,
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
        if (m->needed_count == 16) { say(why, "the image needs more than sixteen images"); host->free(m, sizeof *m, host->ctx); return -1; }
        okld_size nsize = 0;
        const void* nbytes = host->find_needed ? host->find_needed(need, &nsize, host->ctx) : nullptr;
        if (!nbytes) { say(why, "the image needs '", need, "', which is not found"); host->free(m, sizeof *m, host->ctx); return -1; }
        okld_module* nm = nullptr;
        const int rc = okld_load(nbytes, nsize, need, host, &nm, why);
        if (host->release_bytes) host->release_bytes(nbytes, nsize, host->ctx);
        if (rc != 0) { host->free(m, sizeof *m, host->ctx); return rc; }
        m->needed[m->needed_count++] = nm;
    }

    // The span, reserved once: the image's parts lie at fixed distances.
    const okld_size g = host->granularity(host->ctx);
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (v.ph[k].type == elf::pt_load && v.ph[k].vaddr + v.ph[k].memsz > m->span) m->span = v.ph[k].vaddr + v.ph[k].memsz;
    m->span = round_up(m->span, g);
    m->base = static_cast<unsigned char*>(host->reserve(m->span, host->ctx));
    if (!m->base) { say(why, "the address space for the image could not be reserved"); host->free(m, sizeof *m, host->ctx); return -1; }
    fill(m->base, 0, m->span);
    for (unsigned k = 0; k < v.eh->phnum; ++k) {
        const auto& p = v.ph[k];
        if (p.type != elf::pt_load) continue;
        if (p.offset + p.filesz > n) { say(why, "a segment extends beyond the file"); host->release(m->base, m->span, host->ctx); host->free(m, sizeof *m, host->ctx); return -1; }
        copy(m->base + p.vaddr, static_cast<const unsigned char*>(bytes) + p.offset, p.filesz);
    }
    m->entry = v.eh->entry;
    m->phnum = v.eh->phnum;
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (v.ph[k].type == elf::pt_load && v.eh->phoff >= v.ph[k].offset && v.eh->phoff < v.ph[k].offset + v.ph[k].filesz)
            m->phdr = reinterpret_cast<const elf::phdr*>(m->base + v.ph[k].vaddr + (v.eh->phoff - v.ph[k].offset));
    if (!m->phdr) m->phdr = v.ph;   // not mapped: the caller's bytes describe it

    m->symtab = reinterpret_cast<const elf::sym*>(m->base + v.dynamic(elf::dt_symtab));
    m->strtab = reinterpret_cast<const char*>(m->base + v.dynamic(elf::dt_strtab));
    m->strsz = v.dynamic(elf::dt_strsz);
    if (const elf::u64 h = v.dynamic(elf::dt_hash, ~0ull); h != ~0ull) m->hash = reinterpret_cast<const elf::u32*>(m->base + h);
    if (const elf::u64 h = v.dynamic(elf::dt_gnu_hash, ~0ull); h != ~0ull) m->gnu_hash = reinterpret_cast<const elf::u32*>(m->base + h);
    m->init = v.dynamic(elf::dt_init); m->fini = v.dynamic(elf::dt_fini);
    m->init_array = v.dynamic(elf::dt_init_array); m->init_arraysz = v.dynamic(elf::dt_init_arraysz);
    m->fini_array = v.dynamic(elf::dt_fini_array); m->fini_arraysz = v.dynamic(elf::dt_fini_arraysz);

    if (relocate(m, v, host, why) != 0) { host->release(m->base, m->span, host->ctx); host->free(m, sizeof *m, host->ctx); return -1; }

    // Publish what executes; the rest stays writable.
    for (unsigned k = 0; k < v.eh->phnum; ++k) {
        const auto& p = v.ph[k];
        if (p.type != elf::pt_load || !(p.flags & elf::pf_x)) continue;
        const elf::u64 from = round_down(p.vaddr, g), to = round_up(p.vaddr + p.memsz, g);
        if (host->publish(m->base, from, to - from, host->ctx) != 0) {
            say(why, "the environment refused to make the image's instructions executable");
            host->release(m->base, m->span, host->ctx); host->free(m, sizeof *m, host->ctx);
            return -1;
        }
    }
    sync_instructions(m->base, m->base + m->span);

    lock();
    m->next = g_modules;
    g_modules = m;
    unlock();
    announce(m, static_cast<const unsigned char*>(bytes), n);
    *out = m;
    return 0;
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
    m->host->release(m->base, m->span, m->host->ctx);
    m->host->free(m, sizeof *m, m->host->ctx);
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
