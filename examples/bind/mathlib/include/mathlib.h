/* mathlib --- a library published as an ok image (libmathlib.okso) and this
 * header. A program of any system includes it and calls it; on a system that
 * is not openkal, mcpplibs.openkal-bind generates the binding (docs/bind.md). */
#ifndef MATHLIB_H
#define MATHLIB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mathlib_point { int32_t x, y; };

/* Called by mathlib_each for each value, with the context it was given. */
typedef void (*mathlib_visit)(int32_t value, void* context);

int64_t              mathlib_add(int64_t a, int64_t b);
double               mathlib_scale(double value, double by);
struct mathlib_point mathlib_mirror(struct mathlib_point p);
size_t               mathlib_length(const char* text);
int32_t              mathlib_each(const int32_t* values, size_t count, mathlib_visit visit, void* context);

#ifdef __cplusplus
}
#endif
#endif
