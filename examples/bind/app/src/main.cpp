#include "mathlib.h"
#include <cstdio>

namespace {
// A callback the image calls: on x86-64 Windows it is reached through a
// System V entry the binding gives the image.
void visit(int32_t value, void* context) { *static_cast<long long*>(context) += value; }
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
    return sum == 42 && p.x == -3 && p.y == 7 && n == 4 && total == 10 ? 0 : 1;
}
