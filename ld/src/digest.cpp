// The two digests an okb uses (docs/okb.md): SHA-256 for each member's
// content, as the manifest states it, and the CRC-32 of the ZIP container,
// which every ZIP reader checks. Written out, as the rest of this library is:
// nothing here asks for a C library.
#include <okld.h>
#include "bytes.h"

namespace {

using u8 = unsigned char; using u32 = unsigned int; using u64 = unsigned long long;

// --- SHA-256 (FIPS 180-4) ---------------------------------------------------

constexpr u32 K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

constexpr u32 rotr(u32 x, int c) { return (x >> c) | (x << (32 - c)); }

struct sha256 {
    u32 h[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    u8  buf[64];
    u64 held = 0, total = 0;

    void block(const u8* m) {
        u32 w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (u32(m[4 * i]) << 24) | (u32(m[4 * i + 1]) << 16) | (u32(m[4 * i + 2]) << 8) | u32(m[4 * i + 3]);
        for (int i = 16; i < 64; ++i) {
            const u32 s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const u32 s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
        for (int i = 0; i < 64; ++i) {
            const u32 t1 = k + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
            const u32 t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
    }
    void update(const u8* m, u64 n) {
        total += n;
        while (n > 0) {
            if (held == 0 && n >= 64) { block(m); m += 64; n -= 64; continue; }
            const u64 take = (64 - held) < n ? (64 - held) : n;
            for (u64 i = 0; i < take; ++i) buf[held + i] = m[i];
            held += take; m += take; n -= take;
            if (held == 64) { block(buf); held = 0; }
        }
    }
    void final(u8 out[32]) {
        const u64 bits = total * 8;
        const u8 one = 0x80, zero = 0;
        update(&one, 1);
        while (held != 56) update(&zero, 1);
        u8 len[8];
        for (int i = 0; i < 8; ++i) len[i] = static_cast<u8>(bits >> (56 - 8 * i));
        update(len, 8);
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j) out[4 * i + j] = static_cast<u8>(h[i] >> (24 - 8 * j));
    }
};

// --- CRC-32 (ISO 3309, the ZIP container's) ---------------------------------

struct crc_table {
    u32 v[256];
    constexpr crc_table() : v{} {
        for (u32 i = 0; i < 256; ++i) {
            u32 c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
            v[i] = c;
        }
    }
};
constexpr crc_table kCrc{};

}  // namespace

extern "C" void okld_sha256(const void* bytes, okld_size n, unsigned char out[32]) {
    sha256 s;
    s.update(static_cast<const u8*>(bytes), n);
    s.final(out);
}

extern "C" okld_u32 okld_crc32(okld_u32 crc, const void* bytes, okld_size n) {
    const auto* p = static_cast<const u8*>(bytes);
    u32 c = ~crc;
    for (okld_size i = 0; i < n; ++i) c = kCrc.v[(c ^ p[i]) & 0xff] ^ (c >> 8);
    return ~c;
}
