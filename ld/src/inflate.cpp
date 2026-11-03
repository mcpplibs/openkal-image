// DEFLATE, read (RFC 1951): the bytes of an okb member stored compressed
// (ZIP method 8), which a runner expands once before it maps the image
// (docs/okb.md, 0.4). Freestanding, as the rest of this library is: the caller
// gives the output and nothing is allocated.
#include <okld.h>

namespace {

using u8 = unsigned char; using u16 = unsigned short; using u32 = unsigned int; using u64 = unsigned long long;

struct reader {
    const u8* in; u64 n, at = 0;
    u32 bits = 0; int count = 0;
    bool failed = false;
    // `need' bits, least significant first.
    u32 take(int need) {
        u64 v = bits;
        while (count < need) {
            if (at == n) { failed = true; return 0; }
            v |= u64(in[at++]) << count;
            count += 8;
        }
        bits = u32(v >> need);
        count -= need;
        return u32(v & ((u64(1) << need) - 1));
    }
};

// A canonical Huffman code: how many codes of each length, and the symbols in
// the order of their codes.
struct code {
    u16 counts[16];
    u16 symbols[288];
};

bool build(code& c, const u8* lengths, int n) {
    for (int i = 0; i < 16; ++i) c.counts[i] = 0;
    for (int i = 0; i < n; ++i) c.counts[lengths[i]]++;
    if (c.counts[0] == n) return true;   // no code at all: legal for distances
    int left = 1;
    for (int len = 1; len < 16; ++len) {
        left <<= 1;
        left -= c.counts[len];
        if (left < 0) return false;      // more codes than the lengths allow
    }
    u16 offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; ++len) offs[len + 1] = u16(offs[len] + c.counts[len]);
    for (int i = 0; i < n; ++i)
        if (lengths[i] != 0) c.symbols[offs[lengths[i]]++] = u16(i);
    return true;
}

int decode(reader& r, const code& c) {
    int value = 0, first = 0, index = 0;
    for (int len = 1; len < 16; ++len) {
        value |= int(r.take(1));
        if (r.failed) return -1;
        const int count = c.counts[len];
        if (value - count < first) return c.symbols[index + (value - first)];
        index += count;
        first += count;
        first <<= 1;
        value <<= 1;
    }
    return -1;
}

constexpr u16 kLengthBase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                  35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
constexpr u8  kLengthExtra[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                                   3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
constexpr u16 kDistBase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                                257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
constexpr u8  kDistExtra[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                                 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

// One block's symbols, through its two codes, into `out'.
bool codes(reader& r, const code& lit, const code& dist, u8* out, u64 cap, u64& at) {
    for (;;) {
        const int sym = decode(r, lit);
        if (sym < 0) return false;
        if (sym < 256) {
            if (at == cap) return false;
            out[at++] = u8(sym);
            continue;
        }
        if (sym == 256) return true;
        const int li = sym - 257;
        if (li >= 29) return false;
        const u64 len = kLengthBase[li] + r.take(kLengthExtra[li]);
        const int di = decode(r, dist);
        if (di < 0 || di >= 30) return false;
        const u64 d = kDistBase[di] + r.take(kDistExtra[di]);
        if (r.failed || d > at || len > cap - at) return false;
        for (u64 k = 0; k < len; ++k, ++at) out[at] = out[at - d];
    }
}

bool fixed(reader& r, u8* out, u64 cap, u64& at) {
    code lit, dist;
    u8 l[288];
    for (int i = 0; i < 144; ++i) l[i] = 8;
    for (int i = 144; i < 256; ++i) l[i] = 9;
    for (int i = 256; i < 280; ++i) l[i] = 7;
    for (int i = 280; i < 288; ++i) l[i] = 8;
    build(lit, l, 288);
    for (int i = 0; i < 30; ++i) l[i] = 5;
    build(dist, l, 30);
    return codes(r, lit, dist, out, cap, at);
}

bool dynamic(reader& r, u8* out, u64 cap, u64& at) {
    const int nlen = int(r.take(5)) + 257, ndist = int(r.take(5)) + 1, ncode = int(r.take(4)) + 4;
    if (r.failed || nlen > 286 || ndist > 30) return false;
    static constexpr u8 kOrder[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    u8 lengths[320] = {};
    for (int i = 0; i < ncode; ++i) lengths[kOrder[i]] = u8(r.take(3));
    code lencode;
    if (r.failed || !build(lencode, lengths, 19)) return false;
    for (int i = 0; i < 19; ++i) lengths[i] = 0;
    int index = 0;
    while (index < nlen + ndist) {
        int sym = decode(r, lencode);
        if (sym < 0) return false;
        if (sym < 16) { lengths[index++] = u8(sym); continue; }
        u8 len = 0;
        int repeat;
        if (sym == 16) {
            if (index == 0) return false;
            len = lengths[index - 1];
            repeat = 3 + int(r.take(2));
        } else if (sym == 17) {
            repeat = 3 + int(r.take(3));
        } else {
            repeat = 11 + int(r.take(7));
        }
        if (r.failed || index + repeat > nlen + ndist) return false;
        while (repeat--) lengths[index++] = len;
    }
    if (lengths[256] == 0) return false;   // a block that cannot end
    code lit, dist;
    if (!build(lit, lengths, nlen) || !build(dist, lengths + nlen, ndist)) return false;
    return codes(r, lit, dist, out, cap, at);
}

}  // namespace

extern "C" okld_u64 okld_inflate(const void* in, okld_u64 in_size, void* out, okld_u64 cap, int* ok) {
    reader r{ static_cast<const u8*>(in), in_size };
    u8* o = static_cast<u8*>(out);
    u64 at = 0;
    bool last = false, good = true;
    while (!last && good) {
        last = r.take(1) != 0;
        const u32 type = r.take(2);
        if (r.failed) { good = false; break; }
        if (type == 0) {
            // Stored: to a byte boundary, the length and its complement.
            r.bits = 0; r.count = 0;
            if (r.at + 4 > r.n) { good = false; break; }
            const u32 len = u32(r.in[r.at]) | (u32(r.in[r.at + 1]) << 8);
            const u32 nlen = u32(r.in[r.at + 2]) | (u32(r.in[r.at + 3]) << 8);
            r.at += 4;
            if (len != (~nlen & 0xffffu) || r.at + len > r.n || len > cap - at) { good = false; break; }
            for (u32 k = 0; k < len; ++k) o[at++] = r.in[r.at++];
        } else if (type == 1) {
            good = fixed(r, o, cap, at);
        } else if (type == 2) {
            good = dynamic(r, o, cap, at);
        } else {
            good = false;
        }
    }
    if (ok) *ok = good ? 1 : 0;
    return at;
}
