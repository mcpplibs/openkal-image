// The implementation's measurement and names (openkal.prof, openkal.debug), for both runners.
#include <openkal.h>
#include "runner.h"

namespace okrun {

// THE IMPLEMENTATION'S MEASUREMENT AND NAMES (openkal.prof, openkal.debug),
// referred to only where it provides them (0.6): an implementation without
// them is not asked to define a name it does not have (SPEC 6.1).
#if OKRUN_HAS_PROF
kal_uintptr impl_prof_props() { return kal_prof_props(); }
int impl_prof_sample_begin(kal_u32 per_second) { return kal_prof_sample_begin(per_second); }
kal_intptr impl_prof_sample_take(kal_prof_sample* out, kal_uintptr count) { return kal_prof_sample_take(out, count); }
int impl_prof_sample_end() { return kal_prof_sample_end(); }
int impl_prof_touch_begin(const void* at, kal_uintptr size) { return kal_prof_touch_begin(at, size); }
kal_intptr impl_prof_touch_take(kal_uintptr* out, kal_uintptr count) { return kal_prof_touch_take(out, count); }
int impl_prof_touch_end() { return kal_prof_touch_end(); }
#else
kal_uintptr impl_prof_props() { return 0; }
int impl_prof_sample_begin(kal_u32) { return kal_err_not_supported; }
kal_intptr impl_prof_sample_take(kal_prof_sample*, kal_uintptr) { return 0; }
int impl_prof_sample_end() { return kal_err_invalid; }
int impl_prof_touch_begin(const void*, kal_uintptr) { return kal_err_not_supported; }
kal_intptr impl_prof_touch_take(kal_uintptr*, kal_uintptr) { return 0; }
int impl_prof_touch_end() { return kal_err_invalid; }
#endif
#if OKRUN_HAS_DEBUG
kal_uintptr impl_debug_props() { return kal_debug_props(); }
kal_intptr impl_debug_symbolize(kal_uintptr address, char* out, kal_uintptr cap, kal_uintptr* start) {
    return kal_debug_symbolize(address, out, cap, start);
}
#else
kal_uintptr impl_debug_props() { return 0; }
kal_intptr impl_debug_symbolize(kal_uintptr, char*, kal_uintptr, kal_uintptr*) { return -kal_err_not_found; }
#endif

}  // namespace okrun
