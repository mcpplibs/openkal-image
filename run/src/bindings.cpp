// The names an image imports, bound to this process's openkal implementation,
// each presented in the image's convention (SPEC 12.3). Generated from the
// specification's surface (surface.inc), so that no name can be missed.
#include <openkal.h>
#include "image_abi.h"
#include "runner.h"

namespace okrun {

namespace {

// An implementation's function, entered in the image's convention. Where the
// two conventions are one (every host but x86-64 Windows) this is a tail call.
template <auto F> struct present;
template <class R, class... A, R (*F)(A...)>
struct present<F> {
    OKRUN_IMAGE_ABI static R call(A... a) { return F(a...); }
};

// A function the image passes to be entered as a new context: it is the
// image's, so it is entered in the image's convention through a box.
using image_entry = void (OKRUN_IMAGE_ABI*)(void*);
struct box { image_entry fn; void* arg; };

void enter_image(void* p) {
    const box b = *static_cast<box*>(p);
    kal_free(p, sizeof(box), alignof(box));
    b.fn(b.arg);
}

OKRUN_IMAGE_ABI int callback_kal_task_start(image_entry fn, void* arg, struct kal_task* out) {
    auto* b = static_cast<box*>(kal_alloc(sizeof(box), alignof(box)));
    if (!b) return kal_err_no_memory;
    b->fn = fn; b->arg = arg;
    const int rc = kal_task_start(&enter_image, b, out);
    if (rc != kal_ok) kal_free(b, sizeof(box), alignof(box));
    return rc;
}

OKRUN_IMAGE_ABI int callback_kal_task_start_sized(image_entry fn, void* arg, kal_uintptr size, struct kal_task* out) {
    auto* b = static_cast<box*>(kal_alloc(sizeof(box), alignof(box)));
    if (!b) return kal_err_no_memory;
    b->fn = fn; b->arg = arg;
    const int rc = kal_task_start_sized(&enter_image, b, size, out);
    if (rc != kal_ok) kal_free(b, sizeof(box), alignof(box));
    return rc;
}

// The image's own arguments and name (SPEC 12.3), answered by the runner.
kal_intptr give(const char* v, kal_uintptr n, char* out, kal_uintptr cap) {
    if (out && cap) for (kal_uintptr i = 0; i < n && i < cap; ++i) out[i] = v[i];
    return static_cast<kal_intptr>(n);
}
kal_uintptr length(const char* s) { kal_uintptr n = 0; while (s && s[n]) ++n; return n; }

OKRUN_IMAGE_ABI kal_uintptr own_kal_env_arg_count(void) { return static_cast<kal_uintptr>(state().argc); }
OKRUN_IMAGE_ABI kal_intptr own_kal_env_arg(kal_uintptr i, char* out, kal_uintptr cap) {
    if (i >= static_cast<kal_uintptr>(state().argc)) return -kal_err_not_found;
    const char* a = state().argv[i];
    return give(a, length(a), out, cap);
}
OKRUN_IMAGE_ABI kal_intptr own_kal_env_image(char* out, kal_uintptr cap) {
    return state().name ? give(state().name, length(state().name), out, cap) : -kal_err_not_found;
}

#define OKRUN_BIND(n)     { #n, reinterpret_cast<void*>(&present<&::n>::call) },
#define OKRUN_OWN(n)      { #n, reinterpret_cast<void*>(&own_##n) },
#define OKRUN_CALLBACK(n) { #n, reinterpret_cast<void*>(&callback_##n) },

// At namespace scope, so that it is made once at start and no guard is asked
// of a C++ run-time this library may be linked without.
const binding g_table[] = {
#include "surface.inc"
};

}  // namespace

const binding* bindings(unsigned long& count) {
    count = sizeof g_table / sizeof g_table[0];
    return g_table;
}

}  // namespace okrun
