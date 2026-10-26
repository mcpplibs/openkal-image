// Reading and checking an image: bytes only, nothing mapped (clause 12.2,
// 12.4). A tool on any build machine reads images through this.
#include <okld.h>
#include "image.h"

namespace okld {

size view::symbol_count() const {
    if (const auto h = offset_of(dynamic(elf::dt_hash, ~0ull)); h != ~0ull) {
        const auto* w = at<elf::u32>(h, 2);
        return w ? w[1] : 0;
    }
    const auto g = offset_of(dynamic(elf::dt_gnu_hash, ~0ull));
    if (g == ~0ull) return 0;
    const auto* head = at<elf::u32>(g, 4);
    if (!head) return 0;
    const elf::u32 nbuckets = head[0], symoffset = head[1], bloom = head[2];
    const auto buckets_at = g + 16 + static_cast<elf::u64>(bloom) * 8;
    const auto* buckets = at<elf::u32>(buckets_at, nbuckets);
    if (!buckets) return 0;
    elf::u32 last = 0;
    for (elf::u32 i = 0; i < nbuckets; ++i) if (buckets[i] > last) last = buckets[i];
    if (last < symoffset) return symoffset;
    const auto chain_at = buckets_at + static_cast<elf::u64>(nbuckets) * 4;
    for (;; ++last) {
        const auto* c = at<elf::u32>(chain_at + static_cast<elf::u64>(last - symoffset) * 4);
        if (!c) return last;
        if (*c & 1) return last + 1;
    }
}

bool open(const void* bytes, size n, view& v, char* why, size cap) {
    sentence s(why, cap);
    v.data = static_cast<const unsigned char*>(bytes);
    v.len = n;
    v.eh = v.at<elf::ehdr>(0);
    if (!v.eh) { s << "shorter than an ELF header"; return false; }
    const auto& e = *v.eh;
    if (!(e.ident[0] == 0x7f && e.ident[1] == 'E' && e.ident[2] == 'L' && e.ident[3] == 'F')) {
        s << "not ELF: an image is ELF (SPEC 12.2)"; return false;
    }
    if (e.ident[4] != 2 || e.ident[5] != 1) { s << "not 64-bit little-endian ELF (SPEC 12.2)"; return false; }
    if (e.type != elf::et_dyn) { s << "not position-independent (ET_DYN; SPEC 12.2)"; return false; }
    if (e.machine != elf::em_x86_64 && e.machine != elf::em_aarch64) {
        s << "the architecture "; s.num(e.machine); s << " has no fixed convention (SPEC 12.2)"; return false;
    }
    if (e.phentsize != sizeof(elf::phdr)) { s << "program headers of an unexpected size"; return false; }
    v.ph = v.at<elf::phdr>(e.phoff, e.phnum);
    if (!v.ph) { s << "program headers beyond the file"; return false; }
    for (unsigned i = 0; i < e.phnum; ++i)
        if (v.ph[i].type == elf::pt_dynamic) v.dynamic_ph = &v.ph[i];
    return true;
}

unsigned char* find_note(const view& v, unsigned char* writable, elf::u32 type, elf::u32* descsz) {
    for (unsigned i = 0; i < v.eh->phnum; ++i) {
        const auto& p = v.ph[i];
        if (p.type != elf::pt_note) continue;
        elf::u64 at = p.offset, end = p.offset + p.filesz;
        while (at + sizeof(elf::nhdr) <= end) {
            const auto* n = v.at<elf::nhdr>(at);
            if (!n) break;
            const elf::u64 name_at = at + sizeof(elf::nhdr);
            const elf::u64 desc_at = name_at + ((n->namesz + 3u) & ~3u);
            const elf::u64 next = desc_at + ((n->descsz + 3u) & ~3u);
            if (next > end || next > v.len) break;
            if (n->namesz == 8 && equal(reinterpret_cast<const char*>(v.data + name_at), "OPENKAL") && n->type == type) {
                if (descsz) *descsz = n->descsz;
                return writable ? writable + desc_at : const_cast<unsigned char*>(v.data + desc_at);
            }
            at = next;
        }
    }
    return nullptr;
}

}  // namespace okld

using namespace okld;

extern "C" okld_u64 okld_interface_of(const char* n) {
    struct entry { const char* prefix; int bit; };
    static const entry table[] = {
        { "kal_abort", 0 }, { "kal_exit", 0 },
        { "kal_stdin", 1 }, { "kal_stdout", 1 }, { "kal_stderr", 1 }, { "kal_stream_", 1 },
        { "kal_alloc", 2 }, { "kal_free", 2 }, { "kal_memory_", 2 },
        { "kal_env_", 3 }, { "kal_time_", 4 }, { "kal_random_", 5 }, { "kal_fs_", 6 },
        { "kal_process_", 7 }, { "kal_task_", 8 }, { "kal_exec_", 9 }, { "kal_terminal_", 10 },
        { "kal_net_", 11 }, { "kal_datagram_", 12 }, { "kal_space_", 13 }, { "kal_timeout_", 14 },
    };
    for (const auto& e : table) if (starts(n, e.prefix)) return 1ull << e.bit;
    return 0;   // kal_version, kal_interfaces: the specification's self-description
}

extern "C" int okld_read(const void* bytes, okld_size n, okld_info* out, okld_why* why) {
    view v;
    if (!open(bytes, n, v, why ? why->text : nullptr, why ? sizeof why->text : 0)) return -1;
    okld_info i{};
    i.machine = v.eh->machine;
    i.entry = v.eh->entry;
    for (unsigned k = 0; k < v.eh->phnum; ++k) {
        const auto& p = v.ph[k];
        if (p.type == elf::pt_load && p.vaddr + p.memsz > i.span) i.span = p.vaddr + p.memsz;
    }
    elf::u32 sz = 0;
    if (const auto* d = find_note(v, nullptr, 1, &sz); d && sz >= 16) {
        i.has_requirements = 1;
        copy(&i.format_major, d, 4);
        copy(&i.format_minor, d + 4, 4);
        copy(&i.interfaces, d + 8, 8);
    }
    if (const auto* d = find_note(v, nullptr, 2, &sz); d && sz >= 96)
        for (unsigned k = 0; k < 96; ++k) if (d[k]) { i.signed_ = 1; break; }
    size dn = 0;
    if (const auto* d = v.dynamic_table(dn))
        for (size k = 0; k < dn && d[k].tag != elf::dt_null; ++k) if (d[k].tag == elf::dt_needed) ++i.needed_count;
    *out = i;
    return 0;
}

extern "C" void okld_imports(const void* bytes, okld_size n, void (*each)(const char*, void*), void* ctx) {
    view v;
    char why[8];
    if (!open(bytes, n, v, why, sizeof why)) return;
    const auto* syms = v.symbols();
    const auto count = v.symbol_count();
    if (!syms) return;
    for (size k = 1; k < count; ++k)
        if (syms[k].shndx == elf::shn_undef && syms[k].name)
            if (const char* name = v.string(syms[k].name); name && *name) each(name, ctx);
}

extern "C" void okld_exports(const void* bytes, okld_size n, void (*each)(const char*, void*), void* ctx) {
    view v;
    char why[8];
    if (!open(bytes, n, v, why, sizeof why)) return;
    const auto* syms = v.symbols();
    const auto count = v.symbol_count();
    if (!syms) return;
    for (size k = 1; k < count; ++k)
        if (syms[k].shndx != elf::shn_undef && elf::st_bind(syms[k].info) != elf::stb_local && syms[k].name)
            if (const char* name = v.string(syms[k].name); name && *name) each(name, ctx);
}

namespace {
struct checker {
    okld_report report; void* ctx; int failures = 0;
    void fail(const char* s) { ++failures; if (report) report(s, ctx); }
};
}  // namespace

extern "C" int okld_check(const void* bytes, okld_size n, okld_name_test known_kal,
                          okld_name_test exported_elsewhere, okld_report report, void* ctx) {
    checker c{ report, ctx };
    view v;
    char why[256];
    if (!open(bytes, n, v, why, sizeof why)) { c.fail(why); return c.failures; }
    bool loads = false;
    for (unsigned k = 0; k < v.eh->phnum; ++k) {
        const auto& p = v.ph[k];
        if (p.type == elf::pt_interp) c.fail("names an interpreter: an image is loaded by its runner (SPEC 12.1)");
        if (p.type == elf::pt_tls) c.fail("has a thread-local segment: an image's thread-local storage is emulated (SPEC 12.2)");
        if (p.type == elf::pt_load) {
            loads = true;
            if (p.align < 65536 || (p.vaddr % 65536) != (p.offset % 65536)) {
                sentence s(why, sizeof why);
                s << "a loadable segment at "; s.hex(p.vaddr); s << " is aligned to "; s.hex(p.align);
                s << ", less than 65536 (SPEC 12.2; link with -z max-page-size=65536)";
                c.fail(why);
            }
            if ((p.flags & elf::pf_w) && (p.flags & elf::pf_x)) c.fail("a segment is both writable and executable (SPEC 12.2)");
        }
    }
    if (!loads) c.fail("has no loadable segment");
    if (!v.dynamic_ph) c.fail("has no dynamic section: an image is linked -shared or -pie");
    if (v.dynamic(elf::dt_textrel, ~0ull) != ~0ull || (v.dynamic(elf::dt_flags) & elf::df_textrel))
        c.fail("relocates its text (SPEC 12.2: no text relocation)");
    if (v.dynamic(elf::dt_rel, ~0ull) != ~0ull) c.fail("uses REL relocations; an image uses RELA (SPEC 12.2)");

    // Relocation types.
    auto types = [&](elf::i64 tag, elf::i64 size_tag) {
        const auto at = v.offset_of(v.dynamic(tag, ~0ull));
        const auto bytes_ = v.dynamic(size_tag);
        if (at == ~0ull || bytes_ == 0) return;
        const auto* r = v.at<elf::rela>(at, bytes_ / sizeof(elf::rela));
        if (!r) { c.fail("relocations beyond the file"); return; }
        for (size k = 0; k < bytes_ / sizeof(elf::rela); ++k) {
            const auto t = elf::r_type(r[k].info);
            const bool ok = v.eh->machine == elf::em_x86_64
                ? (t == elf::r_x86_64_none || t == elf::r_x86_64_64 || t == elf::r_x86_64_glob_dat
                   || t == elf::r_x86_64_jump_slot || t == elf::r_x86_64_relative)
                : (t == elf::r_aarch64_none || t == elf::r_aarch64_abs64 || t == elf::r_aarch64_glob_dat
                   || t == elf::r_aarch64_jump_slot || t == elf::r_aarch64_relative);
            if (!ok) {
                sentence s(why, sizeof why);
                s << "relocation type "; s.num(t); s << " is not among those SPEC 12.2 allows";
                c.fail(why);
                return;
            }
        }
    };
    types(elf::dt_rela, elf::dt_relasz);
    types(elf::dt_jmprel, elf::dt_pltrelsz);

    // Imports: kal_* that the specification declares, or another image's.
    const auto* syms = v.symbols();
    const auto count = v.symbol_count();
    for (size k = 1; syms && k < count; ++k) {
        if (syms[k].shndx != elf::shn_undef || !syms[k].name) continue;
        const char* name = v.string(syms[k].name);
        if (!name || !*name) continue;
        const bool kal = starts(name, "kal_") && (!known_kal || known_kal(name, ctx));
        const bool other = exported_elsewhere && exported_elsewhere(name, ctx);
        if (!kal && !other && elf::st_bind(syms[k].info) != elf::stb_weak) {
            sentence s(why, sizeof why);
            s << "imports '" << name << "', which is neither a name openkal declares nor one another image exports (SPEC 12.2)";
            c.fail(why);
        }
    }

    elf::u32 sz = 0;
    const auto* req = find_note(v, nullptr, 1, &sz);
    if (!req || sz < 16) c.fail("has no requirements note (OPENKAL, type 1; SPEC 12.4)");
    else {
        elf::u32 major = 0; copy(&major, req, 4);
        if (major != OKLD_FORMAT_MAJOR) c.fail("its requirements note names another major version of the format (SPEC 12.4)");
    }
    return c.failures;
}

extern "C" int okld_set_requirements(void* bytes, okld_size n, okld_u64 interfaces, okld_why* why) {
    view v;
    if (!open(bytes, n, v, why->text, sizeof why->text)) return -1;
    elf::u32 sz = 0;
    auto* d = find_note(v, static_cast<unsigned char*>(bytes), 1, &sz);
    if (!d || sz < 16) {
        sentence(why->text, sizeof why->text) << "no requirements note to write into (SPEC 12.4): link the note object with the image";
        return -1;
    }
    const elf::u32 major = OKLD_FORMAT_MAJOR, minor = OKLD_FORMAT_MINOR;
    copy(d, &major, 4);
    copy(d + 4, &minor, 4);
    copy(d + 8, &interfaces, 8);
    return 0;
}
