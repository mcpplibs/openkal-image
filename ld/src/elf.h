// The part of ELF the ok format uses (SPEC clause 12.2), written out: this
// library is built where no system header describes ELF.
#pragma once

namespace okld::elf {

using u8 = unsigned char; using u16 = unsigned short; using u32 = unsigned int;
using u64 = unsigned long long; using i64 = long long;

struct ehdr {
    u8  ident[16];
    u16 type, machine; u32 version;
    u64 entry, phoff, shoff;
    u32 flags; u16 ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct phdr { u32 type, flags; u64 offset, vaddr, paddr, filesz, memsz, align; };
struct shdr { u32 name, type; u64 flags, addr, offset, size; u32 link, info; u64 addralign, entsize; };
struct dyn  { i64 tag; u64 val; };
struct sym  { u32 name; u8 info, other; u16 shndx; u64 value, size; };
struct rela { u64 offset, info; i64 addend; };
struct nhdr { u32 namesz, descsz, type; };

static_assert(sizeof(ehdr) == 64 && sizeof(phdr) == 56 && sizeof(shdr) == 64);
static_assert(sizeof(dyn) == 16 && sizeof(sym) == 24 && sizeof(rela) == 24);

enum : u32 { et_dyn = 3, em_x86_64 = 62, em_aarch64 = 183 };
enum : u32 { pt_load = 1, pt_dynamic = 2, pt_interp = 3, pt_note = 4, pt_tls = 7, pt_gnu_relro = 0x6474e552 };
enum : u32 { pf_x = 1, pf_w = 2, pf_r = 4 };
enum : u32 { sht_note = 7, sht_symtab = 2, sht_dynsym = 11 };
enum : i64 {
    dt_null = 0, dt_needed = 1, dt_pltrelsz = 2, dt_hash = 4, dt_strtab = 5, dt_symtab = 6,
    dt_rela = 7, dt_relasz = 8, dt_relaent = 9, dt_strsz = 10, dt_init = 12, dt_fini = 13,
    dt_soname = 14, dt_symbolic = 16, dt_rel = 17, dt_pltrel = 20, dt_textrel = 22, dt_jmprel = 23,
    dt_init_array = 25, dt_fini_array = 26, dt_init_arraysz = 27, dt_fini_arraysz = 28,
    dt_flags = 30, dt_relrsz = 35, dt_relr = 36, dt_relrent = 37,
    dt_gnu_hash = 0x6ffffef5,
};
enum : u64 { df_textrel = 0x4 };
enum : u8 { stb_local = 0, stb_global = 1, stb_weak = 2 };
enum : u16 { shn_undef = 0, shn_abs = 0xfff1 };

// The relocations clause 12.2 allows, per architecture.
enum : u32 {
    r_x86_64_none = 0, r_x86_64_64 = 1, r_x86_64_glob_dat = 6, r_x86_64_jump_slot = 7, r_x86_64_relative = 8,
    r_aarch64_none = 0, r_aarch64_abs64 = 257, r_aarch64_glob_dat = 1025, r_aarch64_jump_slot = 1026,
    r_aarch64_relative = 1027,
};

inline u32 r_type(u64 info) { return static_cast<u32>(info & 0xffffffffu); }
inline u32 r_sym(u64 info) { return static_cast<u32>(info >> 32); }
inline u8 st_bind(u8 info) { return static_cast<u8>(info >> 4); }

}  // namespace okld::elf
