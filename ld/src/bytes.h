// Byte operations of the library's own, so that nothing here asks for a C
// library: a runner carries none, and a C library that uses this is being built.
#pragma once

namespace okld {

using size = __SIZE_TYPE__;

// `volatile' keeps a compiler from making these calls to memcpy and memset.
// Eight bytes at a time where both sides are aligned alike, as a segment and
// its place in memory are (SPEC 12.2): an image's tens of megabytes are copied
// once for every start.
using word = unsigned long long __attribute__((may_alias));
using address = __UINTPTR_TYPE__;
inline void copy(void* d, const void* s, size n) {
    auto* a = static_cast<unsigned char*>(d);
    const auto* b = static_cast<const unsigned char*>(s);
    if (((reinterpret_cast<address>(a) ^ reinterpret_cast<address>(b)) & 7) == 0) {
        for (; n > 0 && (reinterpret_cast<address>(a) & 7); --n) *static_cast<volatile unsigned char*>(a++) = *b++;
        for (; n >= 8; n -= 8, a += 8, b += 8)
            *reinterpret_cast<volatile word*>(a) = *reinterpret_cast<const word*>(b);
    }
    for (; n > 0; --n) *static_cast<volatile unsigned char*>(a++) = *b++;
}
inline void fill(void* d, unsigned char v, size n) {
    auto* a = static_cast<unsigned char*>(d);
    for (; n > 0 && (reinterpret_cast<address>(a) & 7); --n) *static_cast<volatile unsigned char*>(a++) = v;
    const word w = 0x0101010101010101ull * v;
    for (; n >= 8; n -= 8, a += 8) *reinterpret_cast<volatile word*>(a) = w;
    for (; n > 0; --n) *static_cast<volatile unsigned char*>(a++) = v;
}
inline bool equal(const char* a, const char* b) {
    for (;; ++a, ++b) { if (*a != *b) return false; if (!*a) return true; }
}
inline bool starts(const char* a, const char* prefix) {
    for (; *prefix; ++a, ++prefix) if (*a != *prefix) return false;
    return true;
}
inline size length(const char* s) { size n = 0; while (s[n]) ++n; return n; }

// A sentence into a fixed buffer: pieces of text and numbers.
struct sentence {
    char* out; size cap; size at = 0;
    sentence(char* o, size c) : out(o), cap(c) { if (cap) out[0] = 0; }
    sentence& operator<<(const char* s) {
        while (s && *s && at + 1 < cap) out[at++] = *s++;
        if (cap) out[at] = 0;
        return *this;
    }
    sentence& hex(unsigned long long v) {
        char b[19] = "0x"; int n = 2; bool started = false;
        for (int sh = 60; sh >= 0; sh -= 4) {
            const int d = static_cast<int>((v >> sh) & 0xf);
            if (d || started || sh == 0) { b[n++] = "0123456789abcdef"[d]; started = true; }
        }
        b[n] = 0;
        return *this << b;
    }
    sentence& num(unsigned long long v) {
        char b[24]; int n = 23; b[n] = 0;
        do { b[--n] = static_cast<char>('0' + v % 10); v /= 10; } while (v);
        return *this << (b + n);
    }
};

}  // namespace okld
