// The two digests an okb uses (docs/okb.md): SHA-256 for each member's
// content, as the manifest states it, and the CRC-32 of the ZIP container,
// which every ZIP reader checks. Written out, as the rest of this library is:
// nothing here asks for a C library.
//
// A runner digests every image it admits from an okb each time it starts one,
// so SHA-256 runs on the processor's own instructions where it has them: the
// SHA extensions on x86_64, found with CPUID; the SHA-256 instructions of ARMv8
// where the compilation target guarantees them (`__ARM_FEATURE_SHA2', every
// Apple arm64 processor), and on Linux where the processor's identification
// register states them. Elsewhere the rounds are written out. A 68 MB image
// took 0.3 to 0.46 s to admit on the CI runners with the rounds alone.
#include <okld.h>
#include "bytes.h"
#if defined(__aarch64__) && (defined(__ARM_FEATURE_SHA2) || defined(__linux__))
#include <arm_neon.h>
#endif

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

// THE PROCESSOR'S INSTRUCTIONS. Each takes the state as h[0..7] and whole
// 64-byte blocks, and computes what `sha256::block' computes for each.
#if defined(__x86_64__)
using v4si = int __attribute__((vector_size(16)));
using v4su = unsigned __attribute__((vector_size(16)));

bool sha_instructions() {
    // CPUID leaf 7: SHA (EBX bit 29). The rounds below use SSE2 alone besides.
    u32 a, b, c, d;
    __asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0u), "c"(0u));
    if (a < 7) return false;
    __asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(7u), "c"(0u));
    return (b >> 29) & 1u;
}

__attribute__((target("sha"))) void blocks_sha(u32 h[8], const u8* m, u64 count) {
    // The instructions hold the state as ABEF and CDGH, A in the highest lane.
    v4su abef = { h[5], h[4], h[1], h[0] }, cdgh = { h[7], h[6], h[3], h[2] };
    for (; count > 0; --count, m += 64) {
        const v4su abef_was = abef, cdgh_was = cdgh;
        v4su w[16];
        for (int i = 0; i < 4; ++i) {
            const u8* q = m + 16 * i;
            for (int j = 0; j < 4; ++j)
                w[i][j] = (u32(q[4 * j]) << 24) | (u32(q[4 * j + 1]) << 16) | (u32(q[4 * j + 2]) << 8) | u32(q[4 * j + 3]);
        }
        for (int g = 0; g < 16; ++g) {
            if (g >= 4) {
                // W[t-16..t-13] + s0, + W[t-7..t-4], then + s1 of W[t-2..t-1].
                const v4su s0 = (v4su)__builtin_ia32_sha256msg1((v4si)w[g - 4], (v4si)w[g - 3]);
                const v4su mid = { w[g - 2][1], w[g - 2][2], w[g - 2][3], w[g - 1][0] };
                w[g] = (v4su)__builtin_ia32_sha256msg2((v4si)(s0 + mid), (v4si)w[g - 1]);
            }
            const v4su k = { K[4 * g], K[4 * g + 1], K[4 * g + 2], K[4 * g + 3] };
            const v4su wk = w[g] + k;
            cdgh = (v4su)__builtin_ia32_sha256rnds2((v4si)cdgh, (v4si)abef, (v4si)wk);
            const v4su high = { wk[2], wk[3], 0u, 0u };
            abef = (v4su)__builtin_ia32_sha256rnds2((v4si)abef, (v4si)cdgh, (v4si)high);
        }
        abef += abef_was;
        cdgh += cdgh_was;
    }
    h[0] = abef[3]; h[1] = abef[2]; h[4] = abef[1]; h[5] = abef[0];
    h[2] = cdgh[3]; h[3] = cdgh[2]; h[6] = cdgh[1]; h[7] = cdgh[0];
}
#elif defined(__aarch64__) && (defined(__ARM_FEATURE_SHA2) || defined(__linux__))
#if defined(__ARM_FEATURE_SHA2)
bool sha_instructions() { return true; }
#define OKLD_SHA2_TARGET
#else
// LINUX STATES THE PROCESSOR'S IDENTIFICATION REGISTERS to programs: it traps
// `mrs' of them and answers with what the processors have in common (4.11,
// HWCAP_CPUID). Before 4.11 the instruction is undefined, so the kernel's
// release is asked first, with the system call itself; nothing here asks for a
// C library. A processor without the instructions (a Cortex-A72 without its
// cryptographic extension) states 0 and keeps the rounds written out.
bool kernel_from_4_11() {
    char u[6][65];
    register long x8 __asm__("x8") = 160;  // uname
    register long x0 __asm__("x0") = reinterpret_cast<long>(&u);
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    if (x0 != 0) return false;
    const char* r = u[2];
    unsigned major = 0, minor = 0;
    for (; *r >= '0' && *r <= '9'; ++r) major = major * 10 + unsigned(*r - '0');
    if (*r == '.') for (++r; *r >= '0' && *r <= '9'; ++r) minor = minor * 10 + unsigned(*r - '0');
    return major > 4 || (major == 4 && minor >= 11);
}
bool sha_instructions() {
    if (!kernel_from_4_11()) return false;
    u64 isar0;
    __asm__("mrs %0, ID_AA64ISAR0_EL1" : "=r"(isar0));
    return ((isar0 >> 12) & 0xf) >= 1;  // SHA2: SHA256H, SHA256H2, SHA256SU0, SHA256SU1
}
#define OKLD_SHA2_TARGET __attribute__((target("arch=armv8-a+sha2")))
#endif

OKLD_SHA2_TARGET void blocks_sha(u32 h[8], const u8* m, u64 count) {
    uint32x4_t abcd = vld1q_u32(h), efgh = vld1q_u32(h + 4);
    for (; count > 0; --count, m += 64) {
        const uint32x4_t abcd_was = abcd, efgh_was = efgh;
        uint32x4_t w[16];
        for (int i = 0; i < 4; ++i) w[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(m + 16 * i)));
        for (int g = 0; g < 16; ++g) {
            if (g >= 4) w[g] = vsha256su1q_u32(vsha256su0q_u32(w[g - 4], w[g - 3]), w[g - 2], w[g - 1]);
            const uint32x4_t wk = vaddq_u32(w[g], vld1q_u32(K + 4 * g));
            const uint32x4_t was = abcd;
            abcd = vsha256hq_u32(abcd, efgh, wk);
            efgh = vsha256h2q_u32(efgh, was, wk);
        }
        abcd = vaddq_u32(abcd, abcd_was);
        efgh = vaddq_u32(efgh, efgh_was);
    }
    vst1q_u32(h, abcd);
    vst1q_u32(h + 4, efgh);
}
#else
bool sha_instructions() { return false; }
void blocks_sha(u32*, const u8*, u64) {}
#endif

struct sha256 {
    u32 h[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    u8  buf[64];
    u64 held = 0, total = 0;
    bool fast = sha_instructions();

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
            if (held == 0 && n >= 64) {
                if (fast) {
                    const u64 whole = n / 64;
                    blocks_sha(h, m, whole);
                    m += whole * 64; n -= whole * 64;
                    continue;
                }
                block(m); m += 64; n -= 64; continue;
            }
            const u64 take = (64 - held) < n ? (64 - held) : n;
            for (u64 i = 0; i < take; ++i) buf[held + i] = m[i];
            held += take; m += take; n -= take;
            if (held == 64) { if (fast) blocks_sha(h, buf, 1); else block(buf); held = 0; }
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
