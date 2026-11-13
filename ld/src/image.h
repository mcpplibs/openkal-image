// A view of an image's bytes: bounds-checked access to what clause 12.2 names.
#pragma once
#include "elf.h"
#include "bytes.h"

namespace okld {

struct view {
    const unsigned char* data = nullptr;
    size                 len = 0;
    const elf::ehdr*     eh = nullptr;
    const elf::phdr*     ph = nullptr;
    const elf::phdr*     dynamic_ph = nullptr;

    // THE CLASS (SPEC 12.2): a sixty-four bit image is read where it lies; a
    // thirty-two bit one (i386) has its header, program headers and dynamic
    // table widened into the forms above when it is opened, so that what reads
    // them reads one form, and its symbols, relocations and words are read
    // through the accessors below, which know its widths.
    bool      wide = true;
    elf::ehdr eh_wide{};
    static constexpr unsigned max_ph32 = 32, max_dyn32 = 160;
    elf::phdr ph_wide[max_ph32];
    elf::dyn  dyn_wide[max_dyn32];
    size      ndyn_wide = 0;

    view() = default;
    view(const view&) = delete;
    view& operator=(const view&) = delete;

    template <class T>
    const T* at(elf::u64 offset, size count = 1) const {
        if (offset > len || count > (len - offset) / sizeof(T)) return nullptr;
        return reinterpret_cast<const T*>(data + offset);
    }

    // The width of an address of the image, which is the width of a word a
    // relocation writes and of a packed relative entry.
    size word() const { return wide ? 8 : 4; }
    elf::u64 word_of(const unsigned char* p) const {
        elf::u64 w = 0;
        copy(&w, p, word());
        return w;
    }
    void put_word(unsigned char* p, elf::u64 value) const { copy(p, &value, word()); }

    // The file offset an address of the image lies at, through the segment
    // that holds it; or ~0 when no segment does.
    elf::u64 offset_of(elf::u64 addr) const {
        for (unsigned i = 0; i < eh->phnum; ++i) {
            const auto& p = ph[i];
            if (p.type == elf::pt_load && addr >= p.vaddr && addr < p.vaddr + p.filesz)
                return p.offset + (addr - p.vaddr);
        }
        return ~0ull;
    }

    const elf::dyn* dynamic_table(size& n) const {
        if (!wide) { n = ndyn_wide; return dyn_wide; }
        n = dynamic_ph ? dynamic_ph->filesz / sizeof(elf::dyn) : 0;
        return dynamic_ph ? at<elf::dyn>(dynamic_ph->offset, n) : nullptr;
    }
    // The dynamic table's value for a tag, or `none'.
    elf::u64 dynamic(elf::i64 tag, elf::u64 none = 0) const {
        size n = 0;
        const auto* d = dynamic_table(n);
        if (!d) return none;
        for (size i = 0; i < n && d[i].tag != elf::dt_null; ++i) if (d[i].tag == tag) return d[i].val;
        return none;
    }

    const char* string(elf::u64 index) const {
        const auto strtab = offset_of(dynamic(elf::dt_strtab, ~0ull));
        const auto strsz = dynamic(elf::dt_strsz);
        if (strtab == ~0ull || index >= strsz || !at<char>(strtab, strsz)) return nullptr;
        const char* s = reinterpret_cast<const char*>(data + strtab + index);
        for (size i = 0; index + i < strsz; ++i) if (s[i] == 0) return s;
        return nullptr;
    }

    // The number of dynamic symbols: DT_HASH says it, and DT_GNU_HASH lets it
    // be computed.
    size symbol_count() const;
    // A dynamic symbol, widened; false beyond the table.
    bool symbol(size index, elf::sym& out) const {
        const auto off = offset_of(dynamic(elf::dt_symtab, ~0ull));
        if (off == ~0ull || index >= symbol_count()) return false;
        return symbol_at(off, index, out);
    }
    // A symbol of a table at a file offset (the dynamic one, or a section's).
    bool symbol_at(elf::u64 table, size index, elf::sym& out) const {
        if (wide) {
            const auto* s = at<elf::sym>(table + index * sizeof(elf::sym));
            if (!s) return false;
            out = *s;
            return true;
        }
        const auto* s = at<elf::sym32>(table + index * sizeof(elf::sym32));
        if (!s) return false;
        out = elf::sym{ s->name, s->info, s->other, s->shndx, s->value, s->size };
        return true;
    }
    size symbol_size() const { return wide ? sizeof(elf::sym) : sizeof(elf::sym32); }

    // A table of RELA relocations (DT_RELA or DT_JMPREL) and its size in bytes:
    // how many it holds, and each, widened.
    size relocation_size() const { return wide ? sizeof(elf::rela) : sizeof(elf::rela32); }
    size relocation_count(elf::i64 tag, elf::i64 size_tag) const {
        const auto at_ = offset_of(dynamic(tag, ~0ull));
        const auto bytes = dynamic(size_tag);
        if (at_ == ~0ull || !at<unsigned char>(at_, bytes)) return 0;
        return bytes / relocation_size();
    }
    elf::rela relocation(elf::i64 tag, size index) const {
        const auto base = offset_of(dynamic(tag, ~0ull)) + index * relocation_size();
        if (wide) return *at<elf::rela>(base);
        const auto* r = at<elf::rela32>(base);
        return elf::rela{ r->offset, elf::r_info(r->info >> 8, r->info & 0xff), r->addend };
    }
};

// The architecture's relative relocation, and its none (SPEC 12.2).
inline elf::u32 relative_type(const view& v) {
    return v.eh->machine == elf::em_x86_64 ? elf::r_x86_64_relative
         : v.eh->machine == elf::em_386    ? elf::r_386_relative
                                           : elf::r_aarch64_relative;
}
inline elf::u32 none_type(const view& v) {
    return v.eh->machine == elf::em_x86_64 ? elf::r_x86_64_none
         : v.eh->machine == elf::em_386    ? elf::r_386_none
                                           : elf::r_aarch64_none;
}

// Opens a view; the sentence says why not.
bool open(const void* bytes, size n, view& v, char* why, size why_cap);

// The descriptor of an OPENKAL note of a type, writable when the bytes are.
unsigned char* find_note(const view& v, unsigned char* writable, elf::u32 type, elf::u32* descsz);

// THE PLACEMENT NOTE (SPEC 12.4, type 3; openkal 0.23): a base, and for each
// writable loadable segment where its bytes computed for that base lie in the
// file. Its descriptor: the base, the count and a zero word, then the entries.
struct placement {
    struct entry { elf::u64 vaddr = 0, offset = 0, size = 0; };
    elf::u64 base = 0;
    elf::u32 count = 0;
    entry    e[8];
};
constexpr elf::u32 placement_note = 3;
// THE TOUCH NOTE (type 4) and A LOADER'S PREPARED COPY (type 5), version 0.4.
constexpr elf::u32 touch_note = 4;
constexpr elf::u32 prepared_note = 5;
constexpr size     placement_descriptor = 16 + 8 * sizeof(placement::entry);

// The placement an image states, read and held to the image: one entry for
// each writable loadable segment with bytes in the file, in ascending order of
// address, its address and its size in the file, its bytes within the file at
// an offset congruent to its address modulo 65536, and a base that is a
// multiple of 65536. False when it states none --- its requirements note states
// a version below 1.1, or its count is zero --- or when what it states does not
// describe the image.
bool read_placement(const view& v, placement& out);

// The relative relocations, RELA's and RELR's, that write the segment at
// `vaddr' of `filesz' bytes, applied for `base' to `seg', which holds the
// segment's bytes as they are in the file. The relocations that name a symbol
// are not applied.
void apply_relative(const view& v, elf::u64 base, unsigned char* seg, elf::u64 vaddr, elf::u64 filesz);

// SHA-256 of `n' bytes with the `hole_n' from `hole' read as zero.
void sha256_except(const void* bytes, size n, size hole, size hole_n, unsigned char out[32]);

// Whether a relocation names a symbol (it is not a relative one), for the
// architecture of the image.
bool names_a_symbol(const view& v, elf::u32 type);

}  // namespace okld
