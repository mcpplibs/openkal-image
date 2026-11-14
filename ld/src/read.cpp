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
    const auto buckets_at = g + 16 + static_cast<elf::u64>(bloom) * word();
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

namespace {
// An i386 image (ELFCLASS32, EM_386): its header, program headers and dynamic
// table widened into the view's own storage.
bool open32(view& v, sentence& s) {
    const auto* e = v.at<elf::ehdr32>(0);
    if (!e) { s << "shorter than an ELF header"; return false; }
    if (e->type != elf::et_dyn) { s << "not position-independent (ET_DYN; SPEC 12.2)"; return false; }
    if (e->machine != elf::em_386) {
        s << "the architecture "; s.num(e->machine); s << " has no fixed convention in the 32-bit class (SPEC 12.2)";
        return false;
    }
    if (e->phentsize != sizeof(elf::phdr32)) { s << "program headers of an unexpected size"; return false; }
    if (e->phnum > view::max_ph32) { s << "more program headers than a 32-bit image is read with"; return false; }
    const auto* ph = v.at<elf::phdr32>(e->phoff, e->phnum);
    if (!ph) { s << "program headers beyond the file"; return false; }
    v.wide = false;
    auto& w = v.eh_wide;
    copy(w.ident, e->ident, sizeof w.ident);
    w.type = e->type; w.machine = e->machine; w.version = e->version;
    w.entry = e->entry; w.phoff = e->phoff; w.shoff = e->shoff;
    w.flags = e->flags; w.ehsize = e->ehsize; w.phentsize = e->phentsize; w.phnum = e->phnum;
    w.shentsize = e->shentsize; w.shnum = e->shnum; w.shstrndx = e->shstrndx;
    v.eh = &v.eh_wide;
    for (unsigned i = 0; i < e->phnum; ++i)
        v.ph_wide[i] = elf::phdr{ ph[i].type, ph[i].flags, ph[i].offset, ph[i].vaddr, ph[i].paddr,
                                  ph[i].filesz, ph[i].memsz, ph[i].align };
    v.ph = v.ph_wide;
    for (unsigned i = 0; i < e->phnum; ++i)
        if (v.ph[i].type == elf::pt_dynamic) v.dynamic_ph = &v.ph[i];
    if (v.dynamic_ph) {
        const auto n = v.dynamic_ph->filesz / sizeof(elf::dyn32);
        const auto* d = v.at<elf::dyn32>(v.dynamic_ph->offset, n);
        if (!d) { s << "a dynamic table beyond the file"; return false; }
        size k = 0;
        for (; k < n && d[k].tag != elf::dt_null; ++k) {
            if (k + 1 >= view::max_dyn32) { s << "a dynamic table longer than a 32-bit image is read with"; return false; }
            v.dyn_wide[k] = elf::dyn{ d[k].tag, d[k].val };
        }
        v.dyn_wide[k] = elf::dyn{ elf::dt_null, 0 };
        v.ndyn_wide = k + 1;
    }
    return true;
}
}  // namespace

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
    if (e.ident[5] != 1) { s << "not little-endian ELF (SPEC 12.2)"; return false; }
    // The class is the architecture's (SPEC 12.2): sixty-four bits for x86-64 and
    // AArch64, thirty-two for i386 (clause 5.5).
    if (e.ident[4] == 1) return open32(v, s);
    if (e.ident[4] != 2) { s << "neither 32-bit nor 64-bit ELF (SPEC 12.2)"; return false; }
    if (e.type != elf::et_dyn) { s << "not position-independent (ET_DYN; SPEC 12.2)"; return false; }
    if (e.machine != elf::em_x86_64 && e.machine != elf::em_aarch64) {
        s << "the architecture "; s.num(e.machine);
        s << (e.machine == elf::em_386 ? " is of the 32-bit class (SPEC 12.2)" : " has no fixed convention (SPEC 12.2)");
        return false;
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
        // openkal 0.18 and 0.20. openkal.map was missing here until 0.2, so an
        // image that imported it required nothing for it in its note.
        { "kal_map_", 15 }, { "kal_region_", 16 }, { "kal_prof_", 17 }, { "kal_debug_", 18 },
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

namespace {
void each_import(const void* bytes, okld_size n, bool weak_too, void (*each)(const char*, void*), void* ctx) {
    view v;
    char why[8];
    if (!open(bytes, n, v, why, sizeof why)) return;
    const auto count = v.symbol_count();
    elf::sym s{};
    for (size k = 1; k < count && v.symbol(k, s); ++k)
        if (s.shndx == elf::shn_undef && s.name && (weak_too || elf::st_bind(s.info) != elf::stb_weak))
            if (const char* name = v.string(s.name); name && *name) each(name, ctx);
}
}  // namespace

extern "C" void okld_imports(const void* bytes, okld_size n, void (*each)(const char*, void*), void* ctx) {
    each_import(bytes, n, true, each, ctx);
}

extern "C" void okld_required_imports(const void* bytes, okld_size n, void (*each)(const char*, void*), void* ctx) {
    each_import(bytes, n, false, each, ctx);
}

extern "C" void okld_exports(const void* bytes, okld_size n, void (*each)(const char*, void*), void* ctx) {
    view v;
    char why[8];
    if (!open(bytes, n, v, why, sizeof why)) return;
    const auto count = v.symbol_count();
    elf::sym s{};
    for (size k = 1; k < count && v.symbol(k, s); ++k)
        if (s.shndx != elf::shn_undef && elf::st_bind(s.info) != elf::stb_local && s.name)
            if (const char* name = v.string(s.name); name && *name) each(name, ctx);
}

namespace {
struct checker {
    okld_report report; void* ctx; int failures = 0;
    void fail(const char* s) { ++failures; if (report) report(s, ctx); }
};

// Each stored segment against the file: the words a relative relocation
// writes hold what it computes for the base, and every other word is the
// file's. Counted rather than copied, since nothing here allocates.
void verify_placement(const view& v, const placement& p, checker& c) {
    const elf::u32 relative = relative_type(v);
    const elf::u64 w = v.word();
    for (elf::u32 i = 0; i < p.count; ++i) {
        const auto& e = p.e[i];
        const elf::u64 file = v.offset_of(e.vaddr);
        if (file == ~0ull) { c.fail("a placed segment has no bytes in the file"); return; }
        const unsigned char* was = v.data + file;
        const unsigned char* now = v.data + e.offset;
        auto word = [&](const unsigned char* b, elf::u64 at) { return v.word_of(b + at); };
        auto inside = [&](elf::u64 at) { return at >= e.vaddr && at <= e.vaddr + e.size && e.size - (at - e.vaddr) >= w; };
        const elf::u64 mask = w == 8 ? ~0ull : 0xffffffffull;
        elf::u64 written = 0, wrong = 0;
        auto expect = [&](elf::u64 at, elf::u64 value) {
            if (!inside(at)) return;
            if (word(was, at - e.vaddr) != (value & mask)) ++written;
            if (word(now, at - e.vaddr) != (value & mask)) ++wrong;
        };
        auto table = [&](elf::i64 tag, elf::i64 size_tag) {
            const auto n = v.relocation_count(tag, size_tag);
            for (size k = 0; k < n; ++k) {
                const auto r = v.relocation(tag, k);
                if (elf::r_type(r.info) == relative) expect(r.offset, p.base + static_cast<elf::u64>(r.addend));
            }
        };
        table(elf::dt_rela, elf::dt_relasz);
        table(elf::dt_jmprel, elf::dt_pltrelsz);
        const auto relr = v.offset_of(v.dynamic(elf::dt_relr, ~0ull));
        const auto relr_n = v.dynamic(elf::dt_relrsz) / w;
        const auto* rr = relr == ~0ull ? nullptr : v.at<unsigned char>(relr, relr_n * w);
        elf::u64 next = 0;
        for (size k = 0; rr && k < relr_n; ++k) {
            const elf::u64 entry = v.word_of(rr + k * w);
            if ((entry & 1) == 0) {
                if (inside(entry)) expect(entry, word(was, entry - e.vaddr) + p.base);
                next = entry + w;
            } else {
                elf::u64 bits = entry >> 1;
                for (elf::u64 j = 0; bits; ++j, bits >>= 1)
                    if ((bits & 1) && inside(next + w * j)) expect(next + w * j, word(was, next + w * j - e.vaddr) + p.base);
                next += (w * 8 - 1) * w;
            }
        }
        elf::u64 differ = 0;
        for (elf::u64 at = 0; at + w <= e.size; at += w) if (word(was, at) != word(now, at)) ++differ;
        for (elf::u64 at = e.size & ~(w - 1); at < e.size; ++at) if (was[at] != now[at]) ++differ;
        if (wrong != 0 || differ != written) {
            c.fail("a placed segment is not its file bytes with the relative relocations applied for the base (SPEC 12.4)");
            return;
        }
    }
}
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
    if (v.dynamic(elf::dt_rel, ~0ull) != ~0ull)
        c.fail(v.wide ? "uses REL relocations; an image uses RELA (SPEC 12.2)"
                      : "uses REL relocations; an image uses RELA (SPEC 12.2; link an i386 image with -z rela)");

    // Relocation types.
    auto types = [&](elf::i64 tag, elf::i64 size_tag) {
        const auto at = v.offset_of(v.dynamic(tag, ~0ull));
        const auto bytes_ = v.dynamic(size_tag);
        if (at == ~0ull || bytes_ == 0) return;
        if (!v.at<unsigned char>(at, bytes_)) { c.fail("relocations beyond the file"); return; }
        const auto n = v.relocation_count(tag, size_tag);
        for (size k = 0; k < n; ++k) {
            const auto t = elf::r_type(v.relocation(tag, k).info);
            const bool ok = v.eh->machine == elf::em_x86_64
                ? (t == elf::r_x86_64_none || t == elf::r_x86_64_64 || t == elf::r_x86_64_glob_dat
                   || t == elf::r_x86_64_jump_slot || t == elf::r_x86_64_relative)
                : v.eh->machine == elf::em_386
                ? (t == elf::r_386_none || t == elf::r_386_32 || t == elf::r_386_glob_dat
                   || t == elf::r_386_jmp_slot || t == elf::r_386_relative)
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
    const auto count = v.symbol_count();
    elf::sym sk{};
    for (size k = 1; k < count && v.symbol(k, sk); ++k) {
        if (sk.shndx != elf::shn_undef || !sk.name) continue;
        const char* name = v.string(sk.name);
        if (!name || !*name) continue;
        const bool kal = starts(name, "kal_") && (!known_kal || known_kal(name, ctx));
        const bool other = exported_elsewhere && exported_elsewhere(name, ctx);
        if (!kal && !other && elf::st_bind(sk.info) != elf::stb_weak) {
            sentence s(why, sizeof why);
            s << "imports '" << name << "', which is neither a name openkal declares nor one another image exports (SPEC 12.2)";
            c.fail(why);
        }
    }

    // A PLACEMENT, WHERE ONE IS STATED, DESCRIBES THE IMAGE (SPEC 12.4, type
    // 3): an entry for each writable segment with bytes in the file, its stored
    // bytes within the file. What they hold is okld_check_placement's question,
    // asked when an image is sealed and not on every load.
    elf::u32 psz = 0;
    if (const auto* pd = find_note(v, nullptr, placement_note, &psz); pd && psz >= 16) {
        elf::u32 count = 0;
        copy(&count, pd + 8, 4);
        placement p;
        if (count != 0 && !read_placement(v, p))
            c.fail("its placement note does not describe its writable segments (SPEC 12.4)");
    }

    // A TOUCH NOTE, WHERE ONE IS STATED, HOLDS WHAT IT COUNTS; A PREPARED COPY
    // IS NO IMAGE (SPEC 12.4, types 4 and 5): a loader writes one for itself,
    // and refuses an image that carries one.
    elf::u32 tsz = 0;
    if (const auto* td = find_note(v, nullptr, touch_note, &tsz); td && tsz >= 8) {
        elf::u32 count = 0;
        copy(&count, td, 4);
        if (8 + static_cast<elf::u64>(count) * 8 > tsz) c.fail("its touch note counts more ranges than it holds (SPEC 12.4)");
    }
    if (find_note(v, nullptr, prepared_note, nullptr))
        c.fail("carries a loader's prepared copy (OPENKAL, type 5), which an image as distributed does not (SPEC 12.4)");

    elf::u32 sz = 0;
    const auto* req = find_note(v, nullptr, 1, &sz);
    if (!req || sz < 16) c.fail("has no requirements note (OPENKAL, type 1; SPEC 12.4)");
    else {
        elf::u32 major = 0; copy(&major, req, 4);
        if (major != OKLD_FORMAT_MAJOR) c.fail("its requirements note names another major version of the format (SPEC 12.4)");
    }
    return c.failures;
}

extern "C" int okld_check_placement(const void* bytes, okld_size n, okld_report report, void* ctx) {
    checker c{report, ctx};
    view v;
    char why[160];
    if (!open(bytes, n, v, why, sizeof why)) { c.fail(why); return c.failures; }
    placement p;
    if (read_placement(v, p)) verify_placement(v, p, c);
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

// --- the symbols of an image's code and data (0.2) -----------------------------
namespace {
// A section header, widened; false beyond the file.
bool section(const okld::view& v, unsigned i, okld::elf::shdr& out) {
    using namespace okld;
    if (v.wide) {
        const auto* sh = v.at<elf::shdr>(v.eh->shoff + static_cast<elf::u64>(i) * sizeof(elf::shdr));
        if (!sh) return false;
        out = *sh;
        return true;
    }
    const auto* sh = v.at<elf::shdr32>(v.eh->shoff + static_cast<elf::u64>(i) * sizeof(elf::shdr32));
    if (!sh) return false;
    out = elf::shdr{ sh->name, sh->type, sh->flags, sh->addr, sh->offset, sh->size, sh->link, sh->info,
                     sh->addralign, sh->entsize };
    return true;
}
}  // namespace

extern "C" okld_u64 okld_symbols(const void* bytes, okld_size size,
                                 void (*each)(okld_u64, okld_u64, const char*, void*), void* ctx) {
    using namespace okld;
    view v;
    char why[8];
    if (!bytes || !each || !open(bytes, size, v, why, sizeof why)) return 0;
    // The section table's symbol table, with its string table; else the
    // dynamic one, whose names are the exports alone.
    elf::u64 table = ~0ull;
    elf::u64 count = 0;
    const char* strings = nullptr;
    elf::u64 strings_size = 0;
    const elf::u64 shentsize = v.wide ? sizeof(elf::shdr) : 40;
    if (v.eh->shoff && v.eh->shentsize == shentsize) {
        for (unsigned i = 0; i < v.eh->shnum && table == ~0ull; ++i) {
            elf::shdr sh{}, str{};
            if (!section(v, i, sh) || sh.type != elf::sht_symtab || sh.link >= v.eh->shnum || !section(v, sh.link, str))
                continue;
            const auto n = sh.size / v.symbol_size();
            const auto* s = v.at<char>(str.offset, str.size);
            if (v.at<unsigned char>(sh.offset, n * v.symbol_size()) && s) {
                table = sh.offset; count = n; strings = s; strings_size = str.size;
            }
        }
    }
    if (table == ~0ull) {
        table = v.offset_of(v.dynamic(elf::dt_symtab, ~0ull));
        count = table == ~0ull ? 0 : v.symbol_count();
    }
    okld_u64 given = 0;
    for (elf::u64 k = 0; k < count; ++k) {
        elf::sym s{};
        if (!v.symbol_at(table, k, s)) break;
        const unsigned type = s.info & 0xf;
        if ((type != 1 /* STT_OBJECT */ && type != 2 /* STT_FUNC */) || s.value == 0
            || s.shndx == elf::shn_undef || s.shndx == elf::shn_abs) continue;
        const char* name = nullptr;
        if (strings) {
            if (s.name >= strings_size) continue;
            name = strings + s.name;
            bool ended = false;
            for (elf::u64 i = s.name; i < strings_size; ++i) if (strings[i] == 0) { ended = true; break; }
            if (!ended) continue;
        } else {
            name = v.string(s.name);
        }
        if (!name || !*name) continue;
        each(s.value, s.size, name, ctx);
        ++given;
    }
    return given;
}
