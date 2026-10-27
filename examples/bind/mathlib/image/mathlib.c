/* The image of mathlib: freestanding C, built for <arch>-openkal as
 * libmathlib.okso (examples/build-image.sh, or `mcpp build --target'). */
#include "../include/mathlib.h"

#define MATHLIB_API __attribute__((visibility("default")))

MATHLIB_API int64_t mathlib_add(int64_t a, int64_t b) { return a + b; }
MATHLIB_API double mathlib_scale(double value, double by) { return value * by; }
MATHLIB_API struct mathlib_point mathlib_mirror(struct mathlib_point p) {
    struct mathlib_point m = { -p.x, -p.y };
    return m;
}
MATHLIB_API size_t mathlib_length(const char* text) {
    size_t n = 0;
    while (text[n]) ++n;
    return n;
}
MATHLIB_API int32_t mathlib_each(const int32_t* values, size_t count, mathlib_visit visit, void* context) {
    for (size_t i = 0; i < count; ++i) visit(values[i], context);
    return (int32_t)count;
}
