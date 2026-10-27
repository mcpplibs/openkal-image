// The ZIP container of an okb (docs/okb.md): a reader of an archive that lies
// in memory, through its central directory, and a writer of an archive whose
// members are stored and, where asked, begin at a multiple of 64 KiB. One
// reader serves okrun (a file read once, an archive carried inside a program)
// and okld (`bundle check'). Freestanding, as the rest of this library is: the
// writer is given its output buffer and allocates nothing.
#include <okld.h>
#include "bytes.h"

namespace {

using namespace okld;
using u8 = unsigned char; using u16 = unsigned short; using u32 = unsigned int; using u64 = unsigned long long;

constexpr u32 kLocal = 0x04034b50u, kCentral = 0x02014b50u, kEnd = 0x06054b50u;
constexpr u32 kEnd64 = 0x06064b50u, kLocator64 = 0x07064b50u;
constexpr u16 kZip64Field = 0x0001;
// The field the writer pads a member's local header with, so that its bytes
// begin at a multiple of the alignment: the alignment (four bytes), then
// zeros. "ok" in the archive's byte order.
constexpr u16 kAlignField = 0x6b6f;
// 1980-01-01 00:00, the earliest DOS date: no time is read, and two archives
// of the same members are the same bytes.
constexpr u16 kDosDate = (0 << 9) | (1 << 5) | 1, kDosTime = 0;

u16 le16(const u8* p) { return static_cast<u16>(p[0] | (p[1] << 8)); }
u32 le32(const u8* p) { return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24); }
u64 le64(const u8* p) { return u64(le32(p)) | (u64(le32(p + 4)) << 32); }

void say(okld_why* why, const char* a, const char* b = nullptr) {
    if (!why) return;
    sentence s(why->text, sizeof why->text);
    s << a; if (b) s << b;
}

// The end of central directory record, searched from the end: it is followed
// by a comment of at most 65535 bytes.
bool find_end(const u8* d, u64 n, u64& at) {
    if (n < 22) return false;
    const u64 lowest = n > 22 + 65535 ? n - 22 - 65535 : 0;
    for (u64 i = n - 22 + 1; i-- > lowest;) {
        if (le32(d + i) == kEnd && i + 22 + le16(d + i + 20) == n) { at = i; return true; }
    }
    return false;
}

}  // namespace

extern "C" int okld_zip_each(const void* bytes, okld_u64 n,
                             int (*each)(const okld_zip_member*, void*), void* ctx, okld_why* why) {
    const auto* d = static_cast<const u8*>(bytes);
    u64 end = 0;
    if (!find_end(d, n, end)) { say(why, "not a ZIP archive: no end of central directory record"); return -1; }
    u64 count = le16(d + end + 10), cd_size = le32(d + end + 12), cd_at = le32(d + end + 16);
    if (count == 0xffff || cd_size == 0xffffffffu || cd_at == 0xffffffffu) {
        // ZIP64: the locator lies just before the record, and names the
        // ZIP64 record that holds the counts and offsets in full.
        if (end < 20 || le32(d + end - 20) != kLocator64) { say(why, "a ZIP64 archive without its locator"); return -1; }
        const u64 at64 = le64(d + end - 20 + 8);
        if (at64 + 56 > n || le32(d + at64) != kEnd64) { say(why, "the ZIP64 end of central directory record is not where its locator says"); return -1; }
        count = le64(d + at64 + 32); cd_size = le64(d + at64 + 40); cd_at = le64(d + at64 + 48);
    }
    if (cd_at > n || cd_size > n - cd_at) { say(why, "the central directory lies beyond the archive"); return -1; }
    u64 at = cd_at;
    for (u64 k = 0; k < count; ++k) {
        if (at + 46 > cd_at + cd_size || le32(d + at) != kCentral) { say(why, "a central directory entry is malformed"); return -1; }
        okld_zip_member m{};
        const u16 flags = le16(d + at + 8);
        m.method = le16(d + at + 10);
        m.crc32 = le32(d + at + 16);
        m.size = le32(d + at + 20);
        m.original = le32(d + at + 24);
        const u16 name_len = le16(d + at + 28), extra_len = le16(d + at + 30), comment_len = le16(d + at + 32);
        m.header = le32(d + at + 42);
        const u64 next = at + 46 + name_len + extra_len + comment_len;
        if (next > cd_at + cd_size) { say(why, "a central directory entry extends beyond the directory"); return -1; }
        m.name = reinterpret_cast<const char*>(d + at + 46);
        m.name_len = name_len;
        // The ZIP64 field states, in this order, each of the three values its
        // 32-bit field could not hold.
        for (u64 e = at + 46 + name_len; e + 4 <= at + 46 + name_len + extra_len;) {
            const u16 id = le16(d + e), len = le16(d + e + 2);
            if (e + 4 + len > at + 46 + name_len + extra_len) break;
            if (id == kZip64Field) {
                u64 f = e + 4;
                if (m.original == 0xffffffffu && f + 8 <= e + 4 + len) { m.original = le64(d + f); f += 8; }
                if (m.size == 0xffffffffu && f + 8 <= e + 4 + len) { m.size = le64(d + f); f += 8; }
                if (m.header == 0xffffffffu && f + 8 <= e + 4 + len) { m.header = le64(d + f); f += 8; }
            }
            e += 4 + len;
        }
        if (flags & 1) { say(why, "an encrypted member: ", "okb members are not encrypted"); return -1; }
        // The member's bytes follow its local header, whose name and extra
        // field may differ in length from the directory's.
        if (m.header + 30 > n || le32(d + m.header) != kLocal) { say(why, "a member's local header is not where the directory says"); return -1; }
        m.data = m.header + 30 + le16(d + m.header + 26) + le16(d + m.header + 28);
        if (m.data > n || m.size > n - m.data) { say(why, "a member's bytes extend beyond the archive"); return -1; }
        if (each) if (const int r = each(&m, ctx)) return r;
        at = next;
    }
    return 0;
}

namespace {
struct find_ctx { const char* name; okld_zip_member* out; bool found; };
}

extern "C" int okld_zip_find(const void* bytes, okld_u64 n, const char* name, okld_zip_member* out, okld_why* why) {
    find_ctx c{ name, out, false };
    const int r = okld_zip_each(bytes, n, [](const okld_zip_member* m, void* p) -> int {
        auto& c = *static_cast<find_ctx*>(p);
        const size len = length(c.name);
        if (m->name_len != len) return 0;
        for (size i = 0; i < len; ++i) if (m->name[i] != c.name[i]) return 0;
        *c.out = *m;
        c.found = true;
        return 1;
    }, &c, why);
    if (r < 0) return r;
    return c.found ? 0 : 1;
}

// --- writing ------------------------------------------------------------------

namespace {

struct writer {
    u8* out; u64 cap; u64 at = 0;
    bool fits(u64 n) const { return out && at + n <= cap; }
    void b(u8 v)  { if (fits(1)) out[at] = v; ++at; }
    void w16(u16 v) { b(u8(v)); b(u8(v >> 8)); }
    void w32(u32 v) { w16(u16(v)); w16(u16(v >> 16)); }
    void w64(u64 v) { w32(u32(v)); w32(u32(v >> 32)); }
    void bytes(const void* p, u64 n) {
        if (fits(n)) copy(out + at, p, n);
        at += n;
    }
    void zeros(u64 n) { if (fits(n)) fill(out + at, 0, n); at += n; }
};

constexpr u64 kMax32 = 0xffffffffull;

}  // namespace

extern "C" okld_u64 okld_zip_write(const okld_zip_input* in, okld_size count, okld_u32 alignment,
                                   void* out, okld_u64 cap) {
    // Two passes over the same arithmetic: the first only counts, so that a
    // caller learns the size before it gives a buffer.
    for (int pass = 0; pass < 2; ++pass) {
        writer w{ pass == 0 ? nullptr : static_cast<u8*>(out), pass == 0 ? 0 : cap };
        bool any64 = count >= 0xffff;
        // Local headers and bytes.
        for (okld_size i = 0; i < count; ++i) {
            const auto& m = in[i];
            const u64 name_len = length(m.name);
            const bool big = m.size >= kMax32;
            u64 extra = big ? 20 : 0;
            if (m.align && alignment > 1) {
                // The bytes begin after 30 + name + extra; the field that pads
                // them is at least eight bytes (its header and the alignment).
                // Fewer than eight bytes of padding cannot be a field, and is
                // laid down between members instead, which a reader that finds
                // members through the central directory does not see.
                u64 r = (alignment - (w.at + 30 + name_len + extra) % alignment) % alignment;
                if (r > 0 && r < 8) { w.zeros(r); r = 0; }
                extra += r;
            }
            const u64 header = w.at;
            if (header >= kMax32) any64 = true;
            w.w32(kLocal);
            w.w16(big ? 45 : 20);
            w.w16(0);                              // flags
            w.w16(0);                              // stored
            w.w16(kDosTime); w.w16(kDosDate);
            const u32 crc = okld_crc32(0, m.bytes, m.size);
            w.w32(crc);
            w.w32(big ? u32(kMax32) : u32(m.size));
            w.w32(big ? u32(kMax32) : u32(m.size));
            w.w16(u16(name_len));
            w.w16(u16(extra));
            w.bytes(m.name, name_len);
            if (big) { w.w16(kZip64Field); w.w16(16); w.w64(m.size); w.w64(m.size); extra -= 20; }
            if (extra > 0) { w.w16(kAlignField); w.w16(u16(extra - 4)); w.w32(alignment); w.zeros(extra - 8); }
            w.bytes(m.bytes, m.size);
        }
        // The central directory. Each local header's offset is found again by
        // the same arithmetic, with a writer that only counts, so that neither
        // pass needs storage of its own.
        const u64 cd_at = w.at;
        {
            writer c{ nullptr, 0 };
            for (okld_size i = 0; i < count; ++i) {
                const auto& m = in[i];
                const u64 name_len = length(m.name);
                const bool big = m.size >= kMax32;
                u64 extra = big ? 20 : 0;
                if (m.align && alignment > 1) {
                    u64 r = (alignment - (c.at + 30 + name_len + extra) % alignment) % alignment;
                    if (r > 0 && r < 8) { c.at += r; r = 0; }
                    extra += r;
                }
                const u64 header = c.at;
                c.at += 30 + name_len + extra + m.size;
                const u32 crc = okld_crc32(0, m.bytes, m.size);
                const bool big_at = header >= kMax32;
                const u64 extra_c = (big ? 16 : 0) + (big_at ? 8 : 0);
                w.w32(kCentral);
                w.w16((3 << 8) | ((big || big_at) ? 45 : 20));   // made by: UNIX
                w.w16((big || big_at) ? 45 : 20);
                w.w16(0); w.w16(0);
                w.w16(kDosTime); w.w16(kDosDate);
                w.w32(crc);
                w.w32(big ? u32(kMax32) : u32(m.size));
                w.w32(big ? u32(kMax32) : u32(m.size));
                w.w16(u16(name_len));
                w.w16(u16(extra_c ? extra_c + 4 : 0));
                w.w16(0); w.w16(0); w.w16(0);
                w.w32(0100644u << 16);                // a regular file, rw-r--r--
                w.w32(big_at ? u32(kMax32) : u32(header));
                w.bytes(m.name, name_len);
                if (extra_c) {
                    w.w16(kZip64Field); w.w16(u16(extra_c));
                    if (big) { w.w64(m.size); w.w64(m.size); }
                    if (big_at) w.w64(header);
                }
            }
        }
        const u64 cd_size = w.at - cd_at;
        if (cd_at >= kMax32 || cd_size >= kMax32) any64 = true;
        if (any64) {
            const u64 at64 = w.at;
            w.w32(kEnd64); w.w64(44);
            w.w16((3 << 8) | 45); w.w16(45);
            w.w32(0); w.w32(0);
            w.w64(count); w.w64(count); w.w64(cd_size); w.w64(cd_at);
            w.w32(kLocator64); w.w32(0); w.w64(at64); w.w32(1);
        }
        w.w32(kEnd);
        w.w16(0); w.w16(0);
        w.w16(any64 ? 0xffff : u16(count)); w.w16(any64 ? 0xffff : u16(count));
        w.w32(any64 ? u32(kMax32) : u32(cd_size));
        w.w32(any64 ? u32(kMax32) : u32(cd_at));
        w.w16(0);
        if (pass == 0 && (!out || cap < w.at)) return w.at;
        if (pass == 1) return w.at;
    }
    return 0;
}
