// The core runner measures nothing (openkal-image 0.6.3). A measurement writes files and names
// processes, which an implementation without openkal.fs and openkal.process does not have; the
// calls the shared bindings make are answered here as the full runner answers them unasked.
#include <openkal.h>
#include "../runner.h"

namespace okrun {

bool profile_active() { return false; }
bool profile_calls() { return false; }
bool profile_samples() { return false; }
bool profile_touches() { return false; }
void profile_phase(const char*) {}
void profile_note(const char*, const char*, kal_u64) {}
void profile_begin_run() {}
void record_call(unsigned long, kal_u64) {}
int profile_counter(const char*, kal_uintptr, const volatile kal_u64*) { return kal_err_not_supported; }
void profile_mark(const char*, kal_uintptr, int) {}
void profile_finish() {}
void profile_loaded(const char*, const void*, kal_u64, const char*, kal_u64) {}
void profile_settle() {}
kal_intptr symbolize(kal_uintptr, char*, kal_uintptr, kal_uintptr*) { return -kal_err_not_found; }

}  // namespace okrun

extern "C" void okrun_profile(const char*) {}
