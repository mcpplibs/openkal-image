#include "mathlib.h"
#include <cstdio>

namespace {
// A callback the image calls: on x86-64 Windows it is reached through a
// System V entry the binding gives the image.
void visit(int32_t value, void* context) { *static_cast<long long*>(context) += value; }

// The caller's floating-point state, which the binding restores after a call.
// On x86-64 it is set as a thread of Windows begins, the x87 at double
// precision, so that every system shows the change and its restoration.
#if defined(__x86_64__)
unsigned short x87_word() {
    unsigned short word = 0;
    __asm__ volatile("fnstcw %0" : "=m"(word));
    return word;
}
void set_x87_word(unsigned short word) { __asm__ volatile("fldcw %0" : : "m"(word)); }
#endif
}

int main() {
    const long long sum = mathlib_add(40, 2);
    std::printf("add: %lld\n", sum);
    std::printf("scale: %.2f\n", mathlib_scale(1.5, 4));
    const mathlib_point p = mathlib_mirror({ 3, -7 });
    std::printf("mirror: %d %d\n", p.x, p.y);
    std::printf("length: %zu\n", mathlib_length("openkal"));
    const int32_t values[] = { 1, 2, 3, 4 };
    long long total = 0;
    const int32_t n = mathlib_each(values, 4, &visit, &total);
    std::printf("each: %d visited, sum %lld\n", n, total);
#if defined(__x86_64__)
    const unsigned short own = x87_word();
    set_x87_word(0x027F);
    const int32_t in_image = mathlib_conventional_fp();
    const bool restored = x87_word() == 0x027F;
    set_x87_word(own);
#else
    const int32_t in_image = mathlib_conventional_fp();
    const bool restored = true;
#endif
    const bool fp = in_image && restored;
    std::printf("fp: %s in the image, %s here\n", in_image ? "the convention's" : "another",
                restored ? "the caller's" : "another");
    return sum == 42 && p.x == -3 && p.y == 7 && n == 4 && total == 10 && fp ? 0 : 1;
}
