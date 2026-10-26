// The signature of an image (SPEC clause 12.4): Ed25519 over the file, with the
// 96 bytes of the signature note's descriptor read as zero.
//
// SHA-512 and Ed25519 are TweetNaCl's (Bernstein, van Gastel, Janssen, Lange,
// Schwabe, Smetsers; public domain), restated in C++ with an incremental hash
// so that an image is hashed where it lies rather than copied beside its
// signature. Verification takes one pass and no allocation.
#include <okld.h>
#include "image.h"

namespace {

using u8 = unsigned char; using u32 = unsigned int; using u64 = unsigned long long; using i64 = long long;
using gf = i64[16];

// --- SHA-512 ----------------------------------------------------------------

u64 dl64(const u8* x) { u64 u = 0; for (int i = 0; i < 8; ++i) u = (u << 8) | x[i]; return u; }
void ts64(u8* x, u64 u) { for (int i = 7; i >= 0; --i) { x[i] = static_cast<u8>(u); u >>= 8; } }
u64 R(u64 x, int c) { return (x >> c) | (x << (64 - c)); }
u64 Ch(u64 x, u64 y, u64 z) { return (x & y) ^ (~x & z); }
u64 Maj(u64 x, u64 y, u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
u64 Sigma0(u64 x) { return R(x, 28) ^ R(x, 34) ^ R(x, 39); }
u64 Sigma1(u64 x) { return R(x, 14) ^ R(x, 18) ^ R(x, 41); }
u64 sigma0(u64 x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
u64 sigma1(u64 x) { return R(x, 19) ^ R(x, 61) ^ (x >> 6); }

const u64 K[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

void blocks(u64 z[8], const u8* m, u64 n) {
    u64 b[8], a[8], w[16], t;
    for (int i = 0; i < 8; ++i) a[i] = z[i];
    while (n >= 128) {
        for (int i = 0; i < 16; ++i) w[i] = dl64(m + 8 * i);
        for (int i = 0; i < 80; ++i) {
            for (int j = 0; j < 8; ++j) b[j] = a[j];
            t = a[7] + Sigma1(a[4]) + Ch(a[4], a[5], a[6]) + K[i] + w[i % 16];
            b[7] = t + Sigma0(a[0]) + Maj(a[0], a[1], a[2]);
            b[3] += t;
            for (int j = 0; j < 8; ++j) a[(j + 1) % 8] = b[j];
            if (i % 16 == 15)
                for (int j = 0; j < 16; ++j)
                    w[j] += w[(j + 9) % 16] + sigma0(w[(j + 1) % 16]) + sigma1(w[(j + 14) % 16]);
        }
        for (int i = 0; i < 8; ++i) { a[i] += z[i]; z[i] = a[i]; }
        m += 128; n -= 128;
    }
}

struct sha512 {
    u64 z[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
    u8 buf[128]; u64 held = 0, total = 0;
    void update(const u8* m, u64 n) {
        total += n;
        while (n > 0) {
            if (held == 0 && n >= 128) {
                const u64 whole = n & ~127ull;
                blocks(z, m, whole);
                m += whole; n -= whole;
                continue;
            }
            const u64 take = (128 - held) < n ? (128 - held) : n;
            for (u64 i = 0; i < take; ++i) buf[held + i] = m[i];
            held += take; m += take; n -= take;
            if (held == 128) { blocks(z, buf, 128); held = 0; }
        }
    }
    void zeros(u64 n) { const u8 zero[32] = {}; while (n) { const u64 k = n < 32 ? n : 32; update(zero, k); n -= k; } }
    void final(u8 out[64]) {
        u8 x[256] = {};
        for (u64 i = 0; i < held; ++i) x[i] = buf[i];
        x[held] = 128;
        const u64 n = held < 112 ? 128 : 256;
        x[n - 9] = static_cast<u8>(total >> 61);
        ts64(x + n - 8, total << 3);
        blocks(z, x, n);
        for (int i = 0; i < 8; ++i) ts64(out + 8 * i, z[i]);
    }
};

// --- the curve ----------------------------------------------------------------

const gf gf0 = {}, gf1 = { 1 },
    D = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 },
    D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 },
    X = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 },
    Y = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 },
    I = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

int vn(const u8* x, const u8* y, int n) { u32 d = 0; for (int i = 0; i < n; ++i) d |= x[i] ^ y[i]; return (1 & ((d - 1) >> 8)) - 1; }
void set(gf r, const gf a) { for (int i = 0; i < 16; ++i) r[i] = a[i]; }
void car(gf o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (1ll << 16);
        const i64 c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}
void sel(gf p, gf q, int b) { const i64 c = ~(b - 1); for (int i = 0; i < 16; ++i) { const i64 t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; } }
void pack25519(u8* o, const gf n) {
    gf m, t;
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    car(t); car(t); car(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) { m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1); m[i - 1] &= 0xffff; }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const int b = static_cast<int>((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) { o[2 * i] = static_cast<u8>(t[i] & 0xff); o[2 * i + 1] = static_cast<u8>(t[i] >> 8); }
}
int neq(const gf a, const gf b) { u8 c[32], d[32]; pack25519(c, a); pack25519(d, b); return vn(c, d, 32); }
u8 par(const gf a) { u8 d[32]; pack25519(d, a); return d[0] & 1; }
void unpack25519(gf o, const u8* n) { for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + (static_cast<i64>(n[2 * i + 1]) << 8); o[15] &= 0x7fff; }
void A(gf o, const gf a, const gf b) { for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i]; }
void Z(gf o, const gf a, const gf b) { for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i]; }
void M(gf o, const gf a, const gf b) {
    i64 t[31] = {};
    for (int i = 0; i < 16; ++i) for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car(o); car(o);
}
void S(gf o, const gf a) { M(o, a, a); }
void inv(gf o, const gf i) { gf c; set(c, i); for (int a = 253; a >= 0; --a) { S(c, c); if (a != 2 && a != 4) M(c, c, i); } set(o, c); }
void pow2523(gf o, const gf i) { gf c; set(c, i); for (int a = 250; a >= 0; --a) { S(c, c); if (a != 1) M(c, c, i); } set(o, c); }

void add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]); Z(t, q[1], q[0]); M(a, a, t);
    A(b, p[0], p[1]); A(t, q[0], q[1]); M(b, b, t);
    M(c, p[3], q[3]); M(c, c, D2);
    M(d, p[2], q[2]); A(d, d, d);
    Z(e, b, a); Z(f, d, c); A(g, d, c); A(h, b, a);
    M(p[0], e, f); M(p[1], h, g); M(p[2], g, f); M(p[3], e, h);
}
void cswap(gf p[4], gf q[4], u8 b) { for (int i = 0; i < 4; ++i) sel(p[i], q[i], b); }
void pack(u8* r, gf p[4]) { gf tx, ty, zi; inv(zi, p[2]); M(tx, p[0], zi); M(ty, p[1], zi); pack25519(r, ty); r[31] ^= static_cast<u8>(par(tx) << 7); }
void scalarmult(gf p[4], gf q[4], const u8* s) {
    set(p[0], gf0); set(p[1], gf1); set(p[2], gf1); set(p[3], gf0);
    for (int i = 255; i >= 0; --i) {
        const u8 b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b); add(q, p); add(p, p); cswap(p, q, b);
    }
}
void scalarbase(gf p[4], const u8* s) { gf q[4]; set(q[0], X); set(q[1], Y); set(q[2], gf1); M(q[3], X, Y); scalarmult(p, q, s); }

const i64 L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
void modL(u8* r, i64 x[64]) {
    i64 carry, j;
    for (i64 i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; ++j) { x[j] += carry - (x[31] >> 4) * L[j]; carry = x[j] >> 8; x[j] &= 255; }
    for (j = 0; j < 32; ++j) x[j] -= carry * L[j];
    for (int i = 0; i < 32; ++i) { x[i + 1] += x[i] >> 8; r[i] = static_cast<u8>(x[i] & 255); }
}
void reduce(u8* r) { i64 x[64]; for (int i = 0; i < 64; ++i) x[i] = r[i]; for (int i = 0; i < 64; ++i) r[i] = 0; modL(r, x); }

int unpackneg(gf r[4], const u8 p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set(r[2], gf1); unpack25519(r[1], p);
    S(num, r[1]); M(den, num, D); Z(num, num, r[2]); A(den, r[2], den);
    S(den2, den); S(den4, den2); M(den6, den4, den2); M(t, den6, num); M(t, t, den);
    pow2523(t, t); M(t, t, num); M(t, t, den); M(t, t, den); M(r[0], t, den);
    S(chk, r[0]); M(chk, chk, den);
    if (neq(chk, num)) M(r[0], r[0], I);
    S(chk, r[0]); M(chk, chk, den);
    if (neq(chk, num)) return -1;
    if (par(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);
    M(r[3], r[0], r[1]);
    return 0;
}

// The message: the file, with the descriptor's 96 bytes read as zero.
void hash_image(sha512& h, const u8* bytes, u64 n, u64 hole) {
    h.update(bytes, hole);
    h.zeros(96);
    h.update(bytes + hole + 96, n - hole - 96);
}

void expand(const u8 seed[32], u8 d[64]) {
    sha512 h; h.update(seed, 32); h.final(d);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;
}

}  // namespace

using namespace okld;

extern "C" void okld_public_key(const unsigned char seed[32], unsigned char key[32]) {
    u8 d[64]; gf p[4];
    expand(seed, d);
    scalarbase(p, d);
    pack(key, p);
}

extern "C" int okld_sign(void* bytes, okld_size n, const unsigned char seed[32], okld_why* why) {
    view v;
    if (!open(bytes, n, v, why->text, sizeof why->text)) return -1;
    elf::u32 sz = 0;
    u8* desc = find_note(v, static_cast<u8*>(bytes), 2, &sz);
    if (!desc || sz < 96) { sentence(why->text, sizeof why->text) << "no signature note to write into (SPEC 12.4)"; return -1; }
    const u64 hole = static_cast<u64>(desc - static_cast<u8*>(bytes));
    const u8* image = static_cast<const u8*>(bytes);

    u8 d[64], pk[32], r[64], h[64];
    expand(seed, d);
    okld_public_key(seed, pk);
    { sha512 s; s.update(d + 32, 32); hash_image(s, image, n, hole); s.final(r); }
    reduce(r);
    gf p[4];
    u8 R_[32];
    scalarbase(p, r);
    pack(R_, p);
    { sha512 s; s.update(R_, 32); s.update(pk, 32); hash_image(s, image, n, hole); s.final(h); }
    reduce(h);
    i64 x[64] = {};
    for (int i = 0; i < 32; ++i) x[i] = r[i];
    for (int i = 0; i < 32; ++i) for (int j = 0; j < 32; ++j) x[i + j] += h[i] * static_cast<i64>(d[j]);
    u8 S_[32];
    modL(S_, x);
    for (int i = 0; i < 32; ++i) desc[i] = pk[i];
    for (int i = 0; i < 32; ++i) desc[32 + i] = R_[i];
    for (int i = 0; i < 32; ++i) desc[64 + i] = S_[i];
    return 0;
}

extern "C" int okld_verify(const void* bytes, okld_size n, unsigned char key[32]) {
    view v;
    char why[8];
    if (!open(bytes, n, v, why, sizeof why)) return -1;
    elf::u32 sz = 0;
    const u8* desc = find_note(v, nullptr, 2, &sz);
    if (!desc || sz < 96) return 0;
    bool any = false;
    for (int i = 0; i < 96; ++i) if (desc[i]) { any = true; break; }
    if (!any) return 0;
    const u64 hole = static_cast<u64>(desc - static_cast<const u8*>(bytes));
    const u8* pk = desc;
    const u8* sig = desc + 32;
    if (key) for (int i = 0; i < 32; ++i) key[i] = pk[i];
    gf p[4], q[4];
    if (unpackneg(q, pk)) return -2;
    u8 h[64];
    { sha512 s; s.update(sig, 32); s.update(pk, 32); hash_image(s, static_cast<const u8*>(bytes), n, hole); s.final(h); }
    reduce(h);
    scalarmult(p, q, h);
    scalarbase(q, sig + 32);
    add(p, q);
    u8 t[32];
    pack(t, p);
    return vn(sig, t, 32) == 0 ? 1 : -3;
}

// For the tests of this file: SHA-512 of a buffer.
extern "C" void okld_sha512_for_test(const void* m, okld_size n, unsigned char out[64]) {
    sha512 s; s.update(static_cast<const u8*>(m), n); s.final(out);
}

// For the tests of this file: Ed25519 over a plain message (RFC 8032 vectors).
extern "C" void okld_ed25519_sign_for_test(const unsigned char seed[32], const void* msg, okld_size n,
                                           unsigned char sig[64]) {
    const u8* m = static_cast<const u8*>(msg);
    u8 d[64], pk[32], r[64], h[64];
    expand(seed, d);
    okld_public_key(seed, pk);
    { sha512 s; s.update(d + 32, 32); s.update(m, n); s.final(r); }
    reduce(r);
    gf p[4];
    scalarbase(p, r);
    pack(sig, p);
    { sha512 s; s.update(sig, 32); s.update(pk, 32); s.update(m, n); s.final(h); }
    reduce(h);
    i64 x[64] = {};
    for (int i = 0; i < 32; ++i) x[i] = r[i];
    for (int i = 0; i < 32; ++i) for (int j = 0; j < 32; ++j) x[i + j] += h[i] * static_cast<i64>(d[j]);
    modL(sig + 32, x);
}
