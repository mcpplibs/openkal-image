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

// THE SAME, COUNTED (okprof `calls', 0.2): each call's duration is added to
// the name's count by its position. Bound instead of `present' only when a
// measurement asked for calls, so an image that is not measured pays nothing.
template <class T> struct returns_nothing { static constexpr bool value = false; };
template <> struct returns_nothing<void> { static constexpr bool value = true; };
template <auto F, unsigned long I> struct counted;
template <class R, class... A, R (*F)(A...), unsigned long I>
struct counted<F, I> {
    OKRUN_IMAGE_ABI static R call(A... a) {
        const kal_u64 t0 = kal_time_monotonic();
        if constexpr (returns_nothing<R>::value) {
            F(a...);
            record_call(I, kal_time_monotonic() - t0);
        } else {
            R r = F(a...);
            record_call(I, kal_time_monotonic() - t0);
            return r;
        }
    }
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

// A library loaded into a program of this system (okrun_open_library) was
// started by nothing this runner entered: its arguments and its name are the
// program's.
OKRUN_IMAGE_ABI kal_uintptr own_kal_env_arg_count(void) {
    if (!state().started) return kal_env_arg_count();
    return static_cast<kal_uintptr>(state().argc);
}
OKRUN_IMAGE_ABI kal_intptr own_kal_env_arg(kal_uintptr i, char* out, kal_uintptr cap) {
    if (!state().started) return kal_env_arg(i, out, cap);
    if (i >= static_cast<kal_uintptr>(state().argc)) return -kal_err_not_found;
    const char* a = state().argv[i];
    return give(a, length(a), out, cap);
}
OKRUN_IMAGE_ABI kal_intptr own_kal_env_image(char* out, kal_uintptr cap) {
    if (state().carried || !state().started) return kal_env_image(out, cap);
    return state().name ? give(state().name, length(state().name), out, cap) : -kal_err_not_found;
}
// The program that runs the image: the runner's own image, as the process's
// implementation names it (SPEC 12.3) --- which with the image's name starts
// the same program again.
OKRUN_IMAGE_ABI kal_intptr own_kal_env_loader(char* out, kal_uintptr cap) {
    return kal_env_image(out, cap);
}

// THE LOADER'S OWN INTERFACES (SPEC 12.3, 0.2): openkal.prof and openkal.debug
// are answered here, and the word of interfaces states them beside the
// implementation's. The program's end is where a measurement writes what it
// measured, so `kal_exit' and `kal_abort' pass through here first.
OKRUN_IMAGE_ABI kal_u64 own_kal_interfaces(void) {
    return kal_interfaces() | KAL_IFACE_PROF | KAL_IFACE_DEBUG;
}
OKRUN_IMAGE_ABI void own_kal_exit(int status) {
    profile_finish();
    kal_exit(status);
}
OKRUN_IMAGE_ABI void own_kal_abort(const char* msg, kal_uintptr len) {
    profile_finish();
    kal_abort(msg, len);
}
OKRUN_IMAGE_ABI int own_kal_prof_active(void) { return profile_active() ? 1 : 0; }
OKRUN_IMAGE_ABI int own_kal_prof_counter(const char* name, kal_uintptr len, const volatile kal_u64* cell) {
    return profile_counter(name, len, cell);
}
OKRUN_IMAGE_ABI void own_kal_prof_mark(const char* name, kal_uintptr len, int begin) {
    profile_mark(name, len, begin);
}
OKRUN_IMAGE_ABI kal_intptr own_kal_debug_symbolize(kal_uintptr address, char* out, kal_uintptr cap,
                                                   kal_uintptr* start) {
    return symbolize(address, out, cap, start);
}

#define OKRUN_BIND(n, i)     { #n, reinterpret_cast<void*>(&present<&::n>::call) },
#define OKRUN_OWN(n, i)      { #n, reinterpret_cast<void*>(&own_##n) },
#define OKRUN_CALLBACK(n, i) { #n, reinterpret_cast<void*>(&callback_##n) },

// At namespace scope, so that it is made once at start and no guard is asked
// of a C++ run-time this library may be linked without.
const binding g_table[] = {
#include "surface.inc"
};

#undef OKRUN_BIND
#define OKRUN_BIND(n, i)     { #n, reinterpret_cast<void*>(&counted<&::n, i>::call) },
const binding g_counted[] = {
#include "surface.inc"
};
static_assert(sizeof g_table / sizeof g_table[0] <= kProfiledNames, "the call counts hold every name");

}  // namespace

const binding* bindings(unsigned long& count) {
    count = sizeof g_table / sizeof g_table[0];
    return profile_calls() ? g_counted : g_table;
}

}  // namespace okrun
