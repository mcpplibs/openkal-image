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

    template <class T>
    const T* at(elf::u64 offset, size count = 1) const {
        if (offset > len || count > (len - offset) / sizeof(T)) return nullptr;
        return reinterpret_cast<const T*>(data + offset);
    }

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

    // The dynamic table's value for a tag, or `none'.
    elf::u64 dynamic(elf::i64 tag, elf::u64 none = 0) const {
        if (!dynamic_ph) return none;
        const auto n = dynamic_ph->filesz / sizeof(elf::dyn);
        const auto* d = at<elf::dyn>(dynamic_ph->offset, n);
        if (!d) return none;
        for (size i = 0; i < n && d[i].tag != elf::dt_null; ++i) if (d[i].tag == tag) return d[i].val;
        return none;
    }
    const elf::dyn* dynamic_table(size& n) const {
        n = dynamic_ph ? dynamic_ph->filesz / sizeof(elf::dyn) : 0;
        return dynamic_ph ? at<elf::dyn>(dynamic_ph->offset, n) : nullptr;
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
    const elf::sym* symbols() const {
        const auto off = offset_of(dynamic(elf::dt_symtab, ~0ull));
        const auto n = symbol_count();
        return off == ~0ull ? nullptr : at<elf::sym>(off, n);
    }
};

// Opens a view; the sentence says why not.
bool open(const void* bytes, size n, view& v, char* why, size why_cap);

// The descriptor of an OPENKAL note of a type, writable when the bytes are.
unsigned char* find_note(const view& v, unsigned char* writable, elf::u32 type, elf::u32* descsz);

}  // namespace okld
