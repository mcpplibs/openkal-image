// Placing an image at its base (SPEC 12.4, type 3; 12.3; openkal 0.23).
//
// An image is position-independent (12.2), so a loader that places it anywhere
// writes, on every start, each address its relative relocations compute: for a
// language server's image, 164 000 of them over the two mebibytes of its
// read-only-after-relocation data, made resident in every one of the 176
// programs a build of its modules starts. A program of the environment linked
// for one address writes none of them, and its read-only data is the file's
// pages. `okld place' computes the writable segments once, for one base chosen
// from the image's bytes, and appends them to the file; a loader given that
// base takes them and applies only the relocations that name a symbol.
#include <okld.h>
#include "image.h"

namespace okld {
namespace {

constexpr elf::u64 alignment = 65536;

// The end of what the ELF describes: segments, program headers and sections.
// What lies beyond it is a placement's stored segments (or nothing).
elf::u64 content_end(const view& v) {
    elf::u64 end = v.eh->phoff + static_cast<elf::u64>(v.eh->phnum) * sizeof(elf::phdr);
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (v.ph[k].offset + v.ph[k].filesz > end) end = v.ph[k].offset + v.ph[k].filesz;
    if (v.eh->shoff) {
        const elf::u64 sh = v.eh->shoff + static_cast<elf::u64>(v.eh->shnum) * v.eh->shentsize;
        if (sh > end) end = sh;
    }
    return end < v.len ? end : v.len;
}

// A writable loadable segment with bytes in the file: one a placement stores.
// One that is only zeros (`.bss' alone) has nothing to store.
bool stored(const elf::phdr& p) { return p.type == elf::pt_load && (p.flags & elf::pf_w) && p.filesz != 0; }

const elf::phdr* writable_segment(const view& v, elf::u64 vaddr) {
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (stored(v.ph[k]) && v.ph[k].vaddr == vaddr) return &v.ph[k];
    return nullptr;
}

unsigned writable_count(const view& v) {
    unsigned n = 0;
    for (unsigned k = 0; k < v.eh->phnum; ++k)
        if (stored(v.ph[k])) ++n;
    return n;
}

// The requirements note states version 1.1 of clause 12.4 or a later one: a
// loader reads a placement only then (12.4).
bool states_placement(const view& v) {
    elf::u32 sz = 0;
    const unsigned char* d = find_note(v, nullptr, 1, &sz);
    if (!d || sz < 8) return false;
    elf::u32 major = 0, minor = 0;
    copy(&major, d, 4);
    copy(&minor, d + 4, 4);
    return major > 1 || (major == 1 && minor >= 1);
}

}  // namespace

bool names_a_symbol(const view& v, elf::u32 type) {
    return v.eh->machine == elf::em_x86_64
        ? type != elf::r_x86_64_none && type != elf::r_x86_64_relative
        : type != elf::r_aarch64_none && type != elf::r_aarch64_relative;
}

bool read_placement(const view& v, placement& out) {
    if (!states_placement(v)) return false;
    elf::u32 sz = 0;
    const unsigned char* d = find_note(v, nullptr, placement_note, &sz);
    if (!d || sz < 16) return false;
    copy(&out.base, d, 8);
    copy(&out.count, d + 8, 4);
    if (out.count == 0 || out.count > 8 || sz < 16 + out.count * sizeof(placement::entry)) return false;
    if (out.base == 0 || out.base % alignment != 0 || out.count != writable_count(v)) return false;
    for (elf::u32 i = 0; i < out.count; ++i) {
        copy(&out.e[i], d + 16 + i * sizeof(placement::entry), sizeof(placement::entry));
        const auto& e = out.e[i];
        if (i > 0 && e.vaddr <= out.e[i - 1].vaddr) return false;
        const elf::phdr* p = writable_segment(v, e.vaddr);
        if (!p || p->filesz != e.size) return false;
        if (e.offset % alignment != e.vaddr % alignment) return false;
        if (e.offset > v.len || e.size > v.len - e.offset) return false;
    }
    return true;
}

void apply_relative(const view& v, elf::u64 base, unsigned char* seg, elf::u64 vaddr, elf::u64 filesz) {
    const bool x86 = v.eh->machine == elf::em_x86_64;
    const elf::u32 relative = x86 ? elf::r_x86_64_relative : elf::r_aarch64_relative;
    auto inside = [&](elf::u64 at) { return at >= vaddr && at <= vaddr + filesz && filesz - (at - vaddr) >= 8; };
    auto table = [&](elf::i64 tag, elf::i64 size_tag) {
        const auto at = v.offset_of(v.dynamic(tag, ~0ull));
        const auto bytes = v.dynamic(size_tag);
        if (at == ~0ull || bytes == 0) return;
        const auto* r = v.at<elf::rela>(at, bytes / sizeof(elf::rela));
        if (!r) return;
        for (size k = 0; k < bytes / sizeof(elf::rela); ++k) {
            if (elf::r_type(r[k].info) != relative || !inside(r[k].offset)) continue;
            const elf::u64 value = base + static_cast<elf::u64>(r[k].addend);
            copy(seg + (r[k].offset - vaddr), &value, 8);
        }
    };
    table(elf::dt_rela, elf::dt_relasz);
    table(elf::dt_jmprel, elf::dt_pltrelsz);
    const auto relr = v.offset_of(v.dynamic(elf::dt_relr, ~0ull));
    const auto relr_bytes = v.dynamic(elf::dt_relrsz);
    if (relr == ~0ull || relr_bytes == 0) return;
    const auto* e = v.at<elf::u64>(relr, relr_bytes / 8);
    if (!e) return;
    auto add = [&](elf::u64 at) {
        if (!inside(at)) return;
        elf::u64 value = 0;
        copy(&value, seg + (at - vaddr), 8);
        value += base;
        copy(seg + (at - vaddr), &value, 8);
    };
    elf::u64 next = 0;
    for (size k = 0; k < relr_bytes / 8; ++k) {
        if ((e[k] & 1) == 0) {
            add(e[k]);
            next = e[k] + 8;
        } else {
            elf::u64 bits = e[k] >> 1;
            for (elf::u64 i = 0; bits; ++i, bits >>= 1)
                if (bits & 1) add(next + 8 * i);
            next += 63 * 8;
        }
    }
}

}  // namespace okld

using namespace okld;

// The bytes the ELF describes with the placement read as zero: the same
// before an image is placed and after, and however often it is.
extern "C" okld_u64 okld_place_base(const void* image, okld_size size) {
    unsigned char d[32];
    view v;
    char why[8];
    elf::u32 sz = 0;
    const unsigned char* note = open(image, size, v, why, sizeof why) ? find_note(v, nullptr, placement_note, &sz) : nullptr;
    const okld_size end = note ? content_end(v) : size;
    const okld_size hole = note ? static_cast<okld_size>(note - static_cast<const unsigned char*>(image)) : 0;
    sha256_except(image, end, hole, note ? sz : 0, d);
    const okld_u64 slot = (static_cast<okld_u64>(d[0]) | static_cast<okld_u64>(d[1]) << 8) & 0xfff;
    return (okld_u64{1} << 44) + slot * (okld_u64{1} << 32);
}

extern "C" okld_u64 okld_place(const void* image, okld_size n, okld_u64 base, void* out, okld_u64 cap,
                               okld_why* asked) {
    okld_why own{};
    okld_why* why = asked ? asked : &own;
    view v;
    if (!open(image, n, v, why->text, sizeof why->text)) return 0;
    elf::u32 sz = 0;
    if (!find_note(v, nullptr, placement_note, &sz) || sz < placement_descriptor) {
        sentence(why->text, sizeof why->text)
            << "no placement note to write into (SPEC 12.4, type 3): link the note object `okld note-source' writes";
        return 0;
    }
    // The signature is over every byte of the file (12.4, type 2), the stored
    // segments too: an image is placed, and then signed.
    elf::u32 ssz = 0;
    if (const unsigned char* sig = find_note(v, nullptr, 2, &ssz)) {
        for (elf::u32 i = 0; i < ssz; ++i)
            if (sig[i]) {
                sentence(why->text, sizeof why->text) << "the image is signed, and its signature is over the bytes a placement adds: place it, then sign it";
                return 0;
            }
    }
    const unsigned count = writable_count(v);
    if (count == 0 || count > 8) {
        sentence(why->text, sizeof why->text) << "the image has no writable segment, or more than eight";
        return 0;
    }
    const elf::u64 end = content_end(v);
    if (base == 0) base = okld_place_base(image, n);
    if (base % alignment != 0) {
        sentence(why->text, sizeof why->text) << "a base that is not a multiple of 65536";
        return 0;
    }
    // Each writable segment after what the ELF describes, at an offset
    // congruent to its address: a loader maps its pages as it maps the file's.
    placement p;
    p.base = base;
    elf::u64 at = end;
    for (unsigned k = 0; k < v.eh->phnum; ++k) {
        const auto& ph = v.ph[k];
        if (!stored(ph)) continue;
        const elf::u64 offset = at + ((ph.vaddr % alignment) + alignment - (at % alignment)) % alignment;
        p.e[p.count++] = { ph.vaddr, offset, ph.filesz };
        at = offset + ph.filesz;
    }
    const elf::u64 total = at;
    if (!out || cap < total) return total;

    auto* o = static_cast<unsigned char*>(out);
    copy(o, image, end);
    fill(o + end, 0, total - end);
    for (elf::u32 i = 0; i < p.count; ++i) {
        const elf::phdr* ph = writable_segment(v, p.e[i].vaddr);
        copy(o + p.e[i].offset, static_cast<const unsigned char*>(image) + ph->offset, ph->filesz);
        apply_relative(v, base, o + p.e[i].offset, ph->vaddr, ph->filesz);
    }
    view w;
    char ignored[8];
    if (!open(o, total, w, ignored, sizeof ignored)) return 0;
    unsigned char* d = find_note(w, o, placement_note, &sz);
    fill(d, 0, sz);
    copy(d, &p.base, 8);
    copy(d + 8, &p.count, 4);
    for (elf::u32 i = 0; i < p.count; ++i) copy(d + 16 + i * sizeof(placement::entry), &p.e[i], sizeof(placement::entry));
    return total;
}

extern "C" int okld_placement(const void* image, okld_size size, okld_u64* base, okld_u32* count) {
    view v;
    char why[8];
    placement p;
    if (!open(image, size, v, why, sizeof why) || !read_placement(v, p)) {
        if (base) *base = 0;
        if (count) *count = 0;
        return 0;
    }
    if (base) *base = p.base;
    if (count) *count = p.count;
    return 1;
}

// --- the touch note (SPEC 12.4, type 4) -------------------------------------------

extern "C" int okld_touch(void* image, okld_size n, const okld_u32* ranges, okld_u32 count, okld_why* why) {
    view v;
    if (!open(image, n, v, why->text, sizeof why->text)) return -1;
    elf::u32 sz = 0;
    unsigned char* d = find_note(v, static_cast<unsigned char*>(image), touch_note, &sz);
    if (!d || sz < 8) {
        sentence(why->text, sizeof why->text)
            << "no touch note to write into (SPEC 12.4, type 4): link the note object `okld note-source' writes";
        return -1;
    }
    if (8 + static_cast<elf::u64>(count) * 8 > sz) {
        sentence(why->text, sizeof why->text) << "more ranges than the touch note holds";
        return -1;
    }
    elf::u32 ssz = 0;
    if (const unsigned char* sig = find_note(v, nullptr, 2, &ssz)) {
        for (elf::u32 i = 0; i < ssz; ++i)
            if (sig[i]) {
                sentence(why->text, sizeof why->text) << "the image is signed, and its signature is over the touch note: note, then sign";
                return -1;
            }
    }
    fill(d, 0, sz);
    const elf::u32 zero = 0;
    copy(d, &count, 4);
    copy(d + 4, &zero, 4);
    copy(d + 8, ranges, static_cast<size>(count) * 8);
    return 0;
}

extern "C" okld_u32 okld_touches(const void* image, okld_size n, okld_u32* out, okld_u32 cap) {
    view v;
    char why[8];
    if (!open(image, n, v, why, sizeof why)) return 0;
    elf::u32 sz = 0;
    const unsigned char* d = find_note(v, nullptr, touch_note, &sz);
    if (!d || sz < 8) return 0;
    elf::u32 count = 0;
    copy(&count, d, 4);
    if (8 + static_cast<elf::u64>(count) * 8 > sz) return 0;
    const elf::u32 given = count < cap ? count : cap;
    if (out) copy(out, d + 8, static_cast<size>(given) * 8);
    return count;
}

// --- a loader's prepared copy (SPEC 12.4, type 5) -------------------------------------
//
// THE FILE: a note of type 5 at its start --- its descriptor the fields of
// okld_prepared_info, then a block entry of three words for each block --- and
// the blocks' bytes, each at an offset congruent to its address modulo 65536,
// so that a loader maps it as it maps an image's own file.

namespace {
constexpr size prepared_fixed = 4 + 4 + 8 + 32 + 4 + 4 + 8 * 5;   // the descriptor before its blocks

void put_info(unsigned char* d, const okld_prepared_info& i) {
    size at = 0;
    auto put = [&](const void* p, size k) { copy(d + at, p, k); at += k; };
    put(&i.version, 4); put(&i.flags, 4); put(&i.base, 8); put(i.digest, 32); put(&i.count, 4); put(&i.reserved, 4);
    put(&i.arena, 8); put(&i.arena_size, 8); put(&i.context, 8); put(&i.start, 8); put(&i.state, 8);
}

void get_info(const unsigned char* d, okld_prepared_info& i) {
    size at = 0;
    auto get = [&](void* p, size k) { copy(p, d + at, k); at += k; };
    get(&i.version, 4); get(&i.flags, 4); get(&i.base, 8); get(i.digest, 32); get(&i.count, 4); get(&i.reserved, 4);
    get(&i.arena, 8); get(&i.arena_size, 8); get(&i.context, 8); get(&i.start, 8); get(&i.state, 8);
}
}  // namespace

extern "C" okld_u64 okld_prepare_blocks(const okld_prepared_info* info, const okld_prepared_block* blocks,
                                        const void* (*source)(okld_u64, okld_u64, void*), void* ctx,
                                        void* out, okld_u64 cap) {
    if (!info || (info->count && !blocks) || !source) return 0;
    const elf::u64 desc = prepared_fixed + static_cast<elf::u64>(info->count) * 24;
    const elf::u64 header = sizeof(elf::nhdr) + 8 + ((desc + 3) & ~3ull);
    // Each block at an offset congruent to its address modulo the alignment.
    elf::u64 at = header;
    for (elf::u32 i = 0; i < info->count; ++i) {
        const elf::u64 offset = at + ((blocks[i].address % alignment) + alignment - (at % alignment)) % alignment;
        at = offset + blocks[i].size;
    }
    const elf::u64 total = at;
    if (!out || cap < total) return total;
    auto* o = static_cast<unsigned char*>(out);
    fill(o, 0, total);
    const elf::nhdr nh{ 8, static_cast<elf::u32>(desc), prepared_note };
    copy(o, &nh, sizeof nh);
    copy(o + sizeof nh, "OPENKAL", 8);
    unsigned char* d = o + sizeof nh + 8;
    put_info(d, *info);
    at = header;
    for (elf::u32 i = 0; i < info->count; ++i) {
        const elf::u64 offset = at + ((blocks[i].address % alignment) + alignment - (at % alignment)) % alignment;
        const okld_prepared_block b{ blocks[i].address, offset, blocks[i].size };
        copy(d + prepared_fixed + i * 24, &b, 24);
        const void* bytes = source(blocks[i].address, blocks[i].size, ctx);
        if (!bytes) return 0;
        copy(o + offset, bytes, blocks[i].size);
        at = offset + blocks[i].size;
    }
    return total;
}

namespace {
// The stored bytes of the writable segment at an address of a base: the file's
// bytes, as they are written into a prepared copy before they are relocated
// there.
struct file_of { const view* v; const unsigned char* image; okld_u64 base; };
const void* file_segment(okld_u64 address, okld_u64, void* c) {
    auto* f = static_cast<file_of*>(c);
    const elf::phdr* p = writable_segment(*f->v, address - f->base);
    return p ? f->image + p->offset : nullptr;
}
}  // namespace

extern "C" okld_u64 okld_prepare(const void* image, okld_size n, okld_u64 base, const unsigned char digest[32],
                                 void* out, okld_u64 cap, okld_why* asked) {
    okld_why own{};
    okld_why* why = asked ? asked : &own;
    view v;
    if (!open(image, n, v, why->text, sizeof why->text)) return 0;
    if (base == 0 || base % alignment != 0) {
        sentence(why->text, sizeof why->text) << "a base that is not a multiple of 65536";
        return 0;
    }
    okld_prepared_info info{};
    info.version = 1;
    info.base = base;
    if (digest) copy(info.digest, digest, 32);
    okld_prepared_block blocks[8];
    for (unsigned k = 0; k < v.eh->phnum && info.count < 8; ++k) {
        const auto& ph = v.ph[k];
        if (!stored(ph)) continue;
        if (ph.offset + ph.filesz > v.len) {
            sentence(why->text, sizeof why->text) << "a segment extends beyond the file";
            return 0;
        }
        blocks[info.count++] = okld_prepared_block{ base + ph.vaddr, 0, ph.filesz };
    }
    if (info.count == 0) {
        sentence(why->text, sizeof why->text) << "the image has no writable segment with bytes in the file";
        return 0;
    }
    file_of f{ &v, static_cast<const unsigned char*>(image), base };
    const okld_u64 total = okld_prepare_blocks(&info, blocks, &file_segment, &f, nullptr, 0);
    if (!out || cap < total) return total;
    // The segments written where they go, and then relocated there.
    auto* o = static_cast<unsigned char*>(out);
    if (okld_prepare_blocks(&info, blocks, &file_segment, &f, out, cap) != total) return 0;
    okld_prepared_info back{};
    okld_prepared_block placed[8];
    if (okld_prepared(o, total, &back, placed, 8) != 0) return 0;
    for (elf::u32 i = 0; i < back.count; ++i) {
        const elf::phdr* p = writable_segment(v, placed[i].address - base);
        if (p) apply_relative(v, base, o + placed[i].offset, p->vaddr, p->filesz);
    }
    return total;
}

extern "C" int okld_prepared(const void* prepared, okld_size n, okld_prepared_info* info, okld_prepared_block* blocks,
                             okld_u32 cap) {
    if (!prepared || !info || n < sizeof(elf::nhdr) + 8 + prepared_fixed) return -1;
    const auto* b = static_cast<const unsigned char*>(prepared);
    elf::nhdr nh{};
    copy(&nh, b, sizeof nh);
    if (nh.namesz != 8 || nh.type != prepared_note || !equal(reinterpret_cast<const char*>(b + sizeof nh), "OPENKAL")) return -1;
    if (nh.descsz < prepared_fixed || sizeof nh + 8 + nh.descsz > n) return -1;
    const unsigned char* d = b + sizeof nh + 8;
    get_info(d, *info);
    if (info->version != 1 || prepared_fixed + static_cast<elf::u64>(info->count) * 24 > nh.descsz) return -1;
    for (elf::u32 i = 0; i < info->count && i < cap; ++i) {
        copy(&blocks[i], d + prepared_fixed + i * 24, 24);
        if (blocks[i].offset > n || blocks[i].size > n - blocks[i].offset) return -1;
    }
    return 0;
}
