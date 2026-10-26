// Byte operations of the library's own, so that nothing here asks for a C
// library: a runner carries none, and a C library that uses this is being built.
#pragma once

namespace okld {

using size = __SIZE_TYPE__;

inline void copy(void* d, const void* s, size n) {
    auto* a = static_cast<volatile unsigned char*>(d);
    const auto* b = static_cast<const unsigned char*>(s);
    for (size i = 0; i < n; ++i) a[i] = b[i];
}
inline void fill(void* d, unsigned char v, size n) {
    auto* a = static_cast<volatile unsigned char*>(d);
    for (size i = 0; i < n; ++i) a[i] = v;
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
