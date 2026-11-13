#include "debug_image.h"
#include "bytes.h"
#include "elf.h"

namespace okld {
namespace {
constexpr elf::u32 progbits = 1, strtab = 3, rela = 4, nobits = 8, rel = 9;
constexpr elf::u64 alloc = 2, compressed = 0x800;

// THE TWO CLASSES (0.6.3). The object a debugger reads is of the image's class:
// the sixty-four bit one keeps its link relocations with their addends (RELA),
// and i386 keeps them as REL, whose addend is the word at the place.
struct class64 {
    using ehdr = elf::ehdr; using shdr = elf::shdr; using sym = elf::sym; using reloc = elf::rela;
    static constexpr elf::u8 ident = 2;
    static constexpr elf::u32 link_relocations = rela;
    static bool machine(elf::u16 m) { return m == elf::em_x86_64 || m == elf::em_aarch64; }
    static elf::u32 r_type(elf::u64 info) { return elf::r_type(info); }
    static elf::u32 r_sym(elf::u64 info) { return elf::r_sym(info); }
    // Elf64_Chdr: type, reserved, size, alignment.
    static constexpr elf::u64 chdr_size = 24;
    static bool chdr(const unsigned char* p, elf::u64& size, elf::u64& alignment) {
        struct { elf::u32 type, reserved; elf::u64 size, alignment; } c{};
        copy(&c, p, sizeof c);
        size = c.size; alignment = c.alignment;
        return c.type == 1 && !c.reserved;
    }
};
struct class32 {
    using ehdr = elf::ehdr32; using shdr = elf::shdr32; using sym = elf::sym32; using reloc = elf::rel32;
    static constexpr elf::u8 ident = 1;
    static constexpr elf::u32 link_relocations = rel;
    static bool machine(elf::u16 m) { return m == elf::em_386; }
    static elf::u32 r_type(elf::u64 info) { return static_cast<elf::u32>(info & 0xff); }
    static elf::u32 r_sym(elf::u64 info) { return static_cast<elf::u32>(info >> 8); }
    // Elf32_Chdr: type, size, alignment.
    static constexpr elf::u64 chdr_size = 12;
    static bool chdr(const unsigned char* p, elf::u64& size, elf::u64& alignment) {
        struct { elf::u32 type, size, alignment; } c{};
        copy(&c, p, sizeof c);
        size = c.size; alignment = c.alignment;
        return c.type == 1;
    }
};

bool fail(okld_why* why, const char* message) {
    if (why) sentence(why->text, sizeof why->text) << "debugger image: " << message;
    return false;
}
bool range(elf::u64 offset, elf::u64 count, elf::u64 size) {
    return offset <= size && count <= size - offset;
}
bool add(elf::u64& size, elf::u64 count) {
    if (count > ~elf::u64{0} - size) return false;
    size += count;
    return true;
}
bool align(elf::u64& size, elf::u64 alignment) {
    if (!alignment) alignment = 1;
    if (alignment & (alignment - 1)) return false;
    return add(size, (alignment - size % alignment) % alignment);
}
template <class C>
const char* name(const unsigned char* bytes, const typename C::shdr& strings, elf::u32 offset) {
    if (offset >= strings.size) return nullptr;
    const char* p = reinterpret_cast<const char*>(bytes + strings.offset + offset);
    for (elf::u64 i = offset; i < strings.size; ++i) if (!p[i - offset]) return p;
    return nullptr;
}
bool debug_section(const char* name) { return starts(name, ".debug_"); }
// Field widths from the x86-64 psABI, AAELF64 and the i386 psABI relocation
// tables. These are bounds checks only; the debugger still performs the
// relocations.
int relocation_width(elf::u16 machine, elf::u32 type) {
    if (machine == elf::em_x86_64) {
        switch (type) {
        case 0: case 35: return 0;
        case 1: case 6: case 7: case 8: case 16: case 17: case 18:
        case 24: case 25: case 27: case 28: case 29: case 30: case 31:
        case 33: case 37: case 38: return 8;
        case 12: case 13: return 2;
        case 14: case 15: return 1;
        case 36: return 16;
        case 2: case 3: case 4: case 9: case 10: case 11: case 19:
        case 20: case 21: case 22: case 23: case 26: case 32: case 34:
        case 39: case 40: case 41: case 42: return 4;
        default: return -1;
        }
    }
    if (machine == elf::em_aarch64) {
        if (type == 0 || type == 256) return 0;
        if (type == 257 || type == 260 || (type >= 1025 && type <= 1032 && type != 1031)) return 8;
        if (type == 259 || type == 262) return 2;
        if (type == 1031) return 16;
        if (type == 258 || type == 261 || (type >= 263 && type <= 313)
            || (type >= 512 && type <= 573)) return 4;
    }
    if (machine == elf::em_386) {
        switch (type) {
        case 0: return 0;
        case 20: case 21: return 2;   // R_386_16, R_386_PC16
        case 22: case 23: return 1;   // R_386_8, R_386_PC8
        default:
            if ((type >= 1 && type <= 11) || (type >= 14 && type <= 19)
                || (type >= 24 && type <= 43)) return 4;
            return -1;
        }
    }
    return -1;
}
bool inflate_section(const unsigned char* source, elf::u64 size,
                     unsigned char* target, elf::u64 capacity) {
    if (size < 6 || (source[0] & 15) != 8 || (source[0] >> 4) > 7
        || ((unsigned(source[0]) << 8) | source[1]) % 31 || (source[1] & 32)) return false;
    int ok = 0;
    const auto got = okld_inflate(source + 2, size - 6, target, capacity, &ok);
    if (!ok || got != capacity) return false;
    elf::u32 a = 1, b = 0;
    for (elf::u64 i = 0; i < got; ++i) { a = (a + target[i]) % 65521; b = (b + a) % 65521; }
    const auto* tail = source + size - 4;
    const elf::u32 expected = (elf::u32(tail[0]) << 24) | (elf::u32(tail[1]) << 16)
                            | (elf::u32(tail[2]) << 8) | tail[3];
    return ((b << 16) | a) == expected;
}
struct buffer {
    const okld_host* host;
    unsigned char* bytes;
    okld_size size;
    ~buffer() { if (bytes) host->free(bytes, size, host->ctx); }
};

// A relocation section the image's link kept for a section of the debugger
// object (its `info' names it), or the image's run-time relocations (no `info',
// or, on i386, of the other form).
template <class C> bool relocations(const typename C::shdr& s) {
    return s.type == C::link_relocations || s.type == rela;
}

template <class C>
bool build(const unsigned char* bytes, okld_size n, okld_u64 base,
           const okld_host* host, void** out, okld_size* out_size, okld_why* why) {
    using shdr = typename C::shdr;
    using sym = typename C::sym;
    using reloc = typename C::reloc;
    if (n < sizeof(typename C::ehdr)) return fail(why, "missing ELF bytes");
    typename C::ehdr header{};
    copy(&header, bytes, sizeof header);
    if (header.ident[0] != 0x7f || header.ident[1] != 'E' || header.ident[2] != 'L'
        || header.ident[3] != 'F' || header.ident[4] != C::ident || header.ident[5] != 1
        || header.type != elf::et_dyn || !C::machine(header.machine)
        || header.shentsize != sizeof(shdr)
        || !header.shnum || header.shstrndx >= header.shnum || header.shoff % alignof(shdr)
        || !range(header.shoff, elf::u64(header.shnum) * sizeof(shdr), n))
        return fail(why, "invalid ELF section table");
    const auto* sections = reinterpret_cast<const shdr*>(bytes + header.shoff);
    const auto& strings = sections[header.shstrndx];
    if (strings.type != strtab || !range(strings.offset, strings.size, n))
        return fail(why, "invalid section names");
    elf::u64 total = n;
    bool has_debug = false, has_debug_relocations = false;
    for (unsigned i = 0; i < header.shnum; ++i) {
        const auto& s = sections[i];
        const char* label = name<C>(bytes, strings, s.name);
        if (!label || (s.type != nobits && !range(s.offset, s.size, n)))
            return fail(why, "section extends outside the file");
        if (s.flags & alloc) {
            elf::u64 address = s.addr;
            if (!add(address, base) || !add(address, s.size)) return fail(why, "placed section address overflow");
        }
        if (starts(label, ".zdebug_")) return fail(why, "legacy GNU compressed debug sections are unsupported");
        has_debug |= s.size && (equal(label, ".debug_info") || equal(label, ".debug_line"));
        if (relocations<C>(s)) {
            // i386's run-time relocations (RELA: `.rela.dyn', `.rela.plt') are data
            // to the debugger; only the link's (REL) are read.
            if (s.type != C::link_relocations) continue;
            if (s.entsize != sizeof(reloc) || s.size % sizeof(reloc)
                || s.offset % alignof(reloc) || s.link >= header.shnum
                || s.info >= header.shnum || (sections[s.link].type != elf::sht_symtab
                                             && sections[s.link].type != elf::sht_dynsym))
                return fail(why, "invalid relocation table");
            if (s.info) {
                const char* target = name<C>(bytes, strings, sections[s.info].name);
                if (!target) return fail(why, "invalid relocation target name");
                has_debug_relocations |= s.size && debug_section(target);
            }
        }
        if (s.type == elf::sht_symtab || s.type == elf::sht_dynsym) {
            if (s.entsize != sizeof(sym) || s.size % sizeof(sym)
                || s.offset % alignof(sym) || s.link >= header.shnum
                || sections[s.link].type != strtab)
                return fail(why, "invalid symbol table");
        }
        if (!(s.flags & compressed)) continue;
        if ((s.flags & alloc) || !debug_section(label) || s.size < C::chdr_size)
            return fail(why, "unsupported compressed section");
        elf::u64 size = 0, alignment = 0;
        if (!C::chdr(bytes + s.offset, size, alignment) || !align(total, alignment) || !add(total, size))
            return fail(why, "unsupported compression or inflated size overflow");
    }
    if (has_debug && !has_debug_relocations)
        return fail(why, "source debugging needs retained link relocations; rebuild with --emit-relocs");
    if (total > ~okld_size{0}) return fail(why, "debugger object is too large");
    buffer result{host, static_cast<unsigned char*>(host->alloc(static_cast<okld_size>(total), host->ctx)), static_cast<okld_size>(total)};
    if (!result.bytes) return fail(why, "no memory for the debugger object");
    if (reinterpret_cast<okld_u64>(result.bytes) % alignof(shdr))
        return fail(why, "allocator returned unaligned ELF storage");
    copy(result.bytes, bytes, n);
    auto* eh = reinterpret_cast<typename C::ehdr*>(result.bytes);
    auto* sh = reinterpret_cast<shdr*>(result.bytes + header.shoff);
    elf::u64 tail = n;
    for (unsigned i = 0; i < header.shnum; ++i) {
        const auto& original = sections[i];
        if (original.flags & alloc) sh[i].addr = static_cast<decltype(sh[i].addr)>(original.addr + base);
        if (!(original.flags & compressed)) continue;
        elf::u64 size = 0, alignment = 0;
        C::chdr(bytes + original.offset, size, alignment);
        const auto previous = tail;
        if (!align(tail, alignment)) return fail(why, "invalid inflated alignment");
        fill(result.bytes + previous, 0, tail - previous);
        if (!inflate_section(bytes + original.offset + C::chdr_size, original.size - C::chdr_size,
                             result.bytes + tail, size)) return fail(why, "invalid compressed debug data");
        sh[i].offset = static_cast<decltype(sh[i].offset)>(tail);
        sh[i].size = static_cast<decltype(sh[i].size)>(size);
        sh[i].addralign = static_cast<decltype(sh[i].addralign)>(alignment ? alignment : 1);
        sh[i].flags &= ~static_cast<decltype(sh[i].flags)>(compressed);
        tail += size;
    }
    // Read original section addresses throughout. Section-table order cannot
    // decide whether a symbol has already seen the placement adjustment.
    for (unsigned i = 0; i < header.shnum; ++i) {
        const auto& s = sections[i];
        if (s.type == elf::sht_symtab || s.type == elf::sht_dynsym) {
            auto* symbols = reinterpret_cast<sym*>(result.bytes + s.offset);
            for (elf::u64 k = 0; k < s.size / sizeof(sym); ++k) {
                auto& symbol = symbols[k];
                if (symbol.shndx == elf::shn_undef || symbol.shndx == elf::shn_abs) continue;
                if (symbol.shndx >= header.shnum || (symbol.info & 15) == 6 /* STT_TLS */)
                    return fail(why, "unsupported symbol section or address");
                const auto& target = sections[symbol.shndx];
                // Linker-defined header symbols (__ehdr_start, __dso_handle)
                // can precede the first allocated section. Express those as
                // absolute runtime addresses, not wrapped relative offsets.
                if (symbol.value < target.addr) {
                    elf::u64 value = symbol.value;
                    if (!(target.flags & alloc) || !add(value, base))
                        return fail(why, "invalid linker-defined symbol address");
                    symbol.value = static_cast<decltype(symbol.value)>(value);
                    symbol.shndx = elf::shn_abs;
                } else symbol.value -= target.addr;
            }
        }
        if (!relocations<C>(s)) continue;
        // Runtime relocations describe the loaded program, not a section of
        // the debugger object. Keep their bytes as ordinary data.
        if (!s.info || s.type != C::link_relocations) { sh[i].type = progbits; sh[i].link = sh[i].info = 0; sh[i].entsize = 0; continue; }
        const auto& target = sections[s.info];
        const auto& table = sections[s.link];
        const auto symbol_count = table.size / sizeof(sym);
        auto* list = reinterpret_cast<reloc*>(result.bytes + s.offset);
        const elf::u64 target_size = sh[s.info].size;
        for (elf::u64 k = 0; k < s.size / sizeof(reloc); ++k) {
            auto& r = list[k];
            const elf::u32 type = C::r_type(r.info);
            const int width = relocation_width(header.machine, type);
            if (width == 0) continue;
            if (C::r_sym(r.info) >= symbol_count || r.offset < target.addr
                || width < 0 || !range(r.offset - target.addr, static_cast<elf::u64>(width), target_size))
                return fail(why, "relocation is outside its target section");
            if constexpr (C::link_relocations == rel) {
                // The word at the place is the value the link wrote, S + A
                // (R_386_32) or S + A - P (R_386_PC32); the debugger reads it as
                // the addend A and adds its own S (and subtracts its own P).
                if (type == 1 || type == 2) {
                    sym symbol{};
                    copy(&symbol, bytes + table.offset + elf::u64(C::r_sym(r.info)) * sizeof(sym), sizeof symbol);
                    auto* place = result.bytes + sh[s.info].offset + (r.offset - target.addr);
                    elf::u32 word = 0;
                    copy(&word, place, sizeof word);
                    word -= symbol.value;
                    if (type == 2) word += r.offset;
                    copy(place, &word, sizeof word);
                }
            }
            r.offset -= target.addr;
        }
    }
    eh->type = 1; // ET_REL: the debugger applies retained debug relocations.
    eh->entry = eh->phoff = 0;
    eh->phnum = eh->phentsize = 0;
    *out = result.bytes;
    *out_size = result.size;
    result.bytes = nullptr;
    return true;
}
} // namespace

bool debugger_image(const void* input, okld_size n, okld_u64 base,
                    const okld_host* host, void** out, okld_size* out_size,
                    okld_why* why) {
    *out = nullptr;
    *out_size = 0;
    if (!input || !host || !host->alloc || !host->free || n < 16)
        return fail(why, "missing ELF bytes or allocation callbacks");
    if (reinterpret_cast<okld_u64>(input) % alignof(elf::shdr))
        return fail(why, "unaligned ELF storage");
    const auto* bytes = static_cast<const unsigned char*>(input);
    if (bytes[4] == class32::ident) return build<class32>(bytes, n, base, host, out, out_size, why);
    return build<class64>(bytes, n, base, host, out, out_size, why);
}
} // namespace okld
