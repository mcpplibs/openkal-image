#include "debug_image.h"
#include "bytes.h"
#include "elf.h"

namespace okld {
namespace {
constexpr elf::u32 progbits = 1, strtab = 3, rela = 4, nobits = 8;
constexpr elf::u64 alloc = 2, compressed = 0x800;
struct compression_header { elf::u32 type, reserved; elf::u64 size, alignment; };
static_assert(sizeof(compression_header) == 24);

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
const char* name(const unsigned char* bytes, const elf::shdr& strings, elf::u32 offset) {
    if (offset >= strings.size) return nullptr;
    const char* p = reinterpret_cast<const char*>(bytes + strings.offset + offset);
    for (elf::u64 i = offset; i < strings.size; ++i) if (!p[i - offset]) return p;
    return nullptr;
}
bool debug_section(const char* name) { return starts(name, ".debug_"); }
// Field widths from the x86-64 psABI and AAELF64 relocation tables. These
// are bounds checks only; the debugger still performs the relocations.
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
} // namespace

bool debugger_image(const void* input, okld_size n, okld_u64 base,
                    const okld_host* host, void** out, okld_size* out_size,
                    okld_why* why) {
    *out = nullptr;
    *out_size = 0;
    if (!input || !host || !host->alloc || !host->free || n < sizeof(elf::ehdr))
        return fail(why, "missing ELF bytes or allocation callbacks");
    if (reinterpret_cast<okld_u64>(input) % alignof(elf::shdr))
        return fail(why, "unaligned ELF storage");
    const auto* bytes = static_cast<const unsigned char*>(input);
    elf::ehdr header{};
    copy(&header, bytes, sizeof header);
    if (header.ident[0] != 0x7f || header.ident[1] != 'E' || header.ident[2] != 'L'
        || header.ident[3] != 'F' || header.ident[4] != 2 || header.ident[5] != 1
        || header.type != elf::et_dyn || (header.machine != elf::em_x86_64 && header.machine != elf::em_aarch64)
        || header.shentsize != sizeof(elf::shdr)
        || !header.shnum || header.shstrndx >= header.shnum || header.shoff % alignof(elf::shdr)
        || !range(header.shoff, elf::u64(header.shnum) * sizeof(elf::shdr), n))
        return fail(why, "invalid ELF64 section table");
    const auto* sections = reinterpret_cast<const elf::shdr*>(bytes + header.shoff);
    const auto& strings = sections[header.shstrndx];
    if (strings.type != strtab || !range(strings.offset, strings.size, n))
        return fail(why, "invalid section names");
    elf::u64 total = n;
    bool has_debug = false, has_debug_relocations = false;
    for (unsigned i = 0; i < header.shnum; ++i) {
        const auto& s = sections[i];
        const char* label = name(bytes, strings, s.name);
        if (!label || (s.type != nobits && !range(s.offset, s.size, n)))
            return fail(why, "section extends outside the file");
        if (s.flags & alloc) {
            auto address = s.addr;
            if (!add(address, base) || !add(address, s.size)) return fail(why, "placed section address overflow");
        }
        if (starts(label, ".zdebug_")) return fail(why, "legacy GNU compressed debug sections are unsupported");
        has_debug |= s.size && (equal(label, ".debug_info") || equal(label, ".debug_line"));
        if (s.type == rela) {
            if (s.entsize != sizeof(elf::rela) || s.size % sizeof(elf::rela)
                || s.offset % alignof(elf::rela) || s.link >= header.shnum
                || s.info >= header.shnum || (sections[s.link].type != elf::sht_symtab
                                             && sections[s.link].type != elf::sht_dynsym))
                return fail(why, "invalid relocation table");
            if (s.info) {
                const char* target = name(bytes, strings, sections[s.info].name);
                if (!target) return fail(why, "invalid relocation target name");
                has_debug_relocations |= s.size && debug_section(target);
            }
        }
        if (s.type == elf::sht_symtab || s.type == elf::sht_dynsym) {
            if (s.entsize != sizeof(elf::sym) || s.size % sizeof(elf::sym)
                || s.offset % alignof(elf::sym) || s.link >= header.shnum
                || sections[s.link].type != strtab)
                return fail(why, "invalid symbol table");
        }
        if (!(s.flags & compressed)) continue;
        if ((s.flags & alloc) || !debug_section(label) || s.size < sizeof(compression_header))
            return fail(why, "unsupported compressed section");
        compression_header c{};
        copy(&c, bytes + s.offset, sizeof c);
        if (c.type != 1 || c.reserved || !align(total, c.alignment) || !add(total, c.size))
            return fail(why, "unsupported compression or inflated size overflow");
    }
    if (has_debug && !has_debug_relocations)
        return fail(why, "source debugging needs retained link relocations; rebuild with --emit-relocs");
    if (total > ~okld_size{0}) return fail(why, "debugger object is too large");
    buffer result{host, static_cast<unsigned char*>(host->alloc(static_cast<okld_size>(total), host->ctx)), static_cast<okld_size>(total)};
    if (!result.bytes) return fail(why, "no memory for the debugger object");
    if (reinterpret_cast<okld_u64>(result.bytes) % alignof(elf::shdr))
        return fail(why, "allocator returned unaligned ELF storage");
    copy(result.bytes, input, n);
    auto* eh = reinterpret_cast<elf::ehdr*>(result.bytes);
    auto* sh = reinterpret_cast<elf::shdr*>(result.bytes + header.shoff);
    elf::u64 tail = n;
    for (unsigned i = 0; i < header.shnum; ++i) {
        const auto& original = sections[i];
        if (original.flags & alloc) sh[i].addr = original.addr + base;
        if (!(original.flags & compressed)) continue;
        compression_header c{};
        copy(&c, bytes + original.offset, sizeof c);
        const auto previous = tail;
        if (!align(tail, c.alignment)) return fail(why, "invalid inflated alignment");
        fill(result.bytes + previous, 0, tail - previous);
        if (!inflate_section(bytes + original.offset + sizeof c, original.size - sizeof c,
                             result.bytes + tail, c.size)) return fail(why, "invalid compressed debug data");
        sh[i].offset = tail;
        sh[i].size = c.size;
        sh[i].addralign = c.alignment ? c.alignment : 1;
        sh[i].flags &= ~compressed;
        tail += c.size;
    }
    // Read original section addresses throughout. Section-table order cannot
    // decide whether a symbol has already seen the placement adjustment.
    for (unsigned i = 0; i < header.shnum; ++i) {
        const auto& s = sections[i];
        if (s.type == elf::sht_symtab || s.type == elf::sht_dynsym) {
            auto* symbols = reinterpret_cast<elf::sym*>(result.bytes + s.offset);
            for (elf::u64 k = 0; k < s.size / sizeof(elf::sym); ++k) {
                auto& symbol = symbols[k];
                if (symbol.shndx == elf::shn_undef || symbol.shndx == elf::shn_abs) continue;
                if (symbol.shndx >= header.shnum || (symbol.info & 15) == 6 /* STT_TLS */)
                    return fail(why, "unsupported symbol section or address");
                const auto& target = sections[symbol.shndx];
                // Linker-defined header symbols (__ehdr_start, __dso_handle)
                // can precede the first allocated section. Express those as
                // absolute runtime addresses, not wrapped relative offsets.
                if (symbol.value < target.addr) {
                    if (!(target.flags & alloc) || !add(symbol.value, base))
                        return fail(why, "invalid linker-defined symbol address");
                    symbol.shndx = elf::shn_abs;
                } else symbol.value -= target.addr;
            }
        }
        if (s.type != rela) continue;
        // Runtime relocations describe the loaded program, not a section of
        // the debugger object. Keep their bytes as ordinary data.
        if (!s.info) { sh[i].type = progbits; sh[i].link = sh[i].info = 0; sh[i].entsize = 0; continue; }
        const auto& target = sections[s.info];
        const auto symbol_count = sections[s.link].size / sizeof(elf::sym);
        auto* relocations = reinterpret_cast<elf::rela*>(result.bytes + s.offset);
        const auto target_size = sh[s.info].size;
        for (elf::u64 k = 0; k < s.size / sizeof(elf::rela); ++k) {
            auto& r = relocations[k];
            const int width = relocation_width(header.machine, elf::r_type(r.info));
            if (width == 0) continue;
            if (elf::r_sym(r.info) >= symbol_count || r.offset < target.addr
                || width < 0 || !range(r.offset - target.addr, static_cast<elf::u64>(width), target_size))
                return fail(why, "relocation is outside its target section");
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
} // namespace okld
