#pragma once
#include <openkal/types.h>
#include <openkal/fs.h>

namespace okrun {

struct binding { const char* name; void* address; };

struct image_state {
    int                argc = 0;
    const char* const* argv = nullptr;
    const char*        name = nullptr;
    bool               carried = false;   // okrun_options::carried
    // An image was entered. Before it is (a library loaded into a program of
    // this system), its arguments and name are the program's own.
    bool               started = false;
};
image_state& state();

const binding* bindings(unsigned long& count);

// --- a measurement, and the names of addresses (0.2, src/prof.cpp) ---------
//
// What OKRUN_PROF (or `okrun --prof') asks for, read once: `calls' binds each
// name through a counting entry, `counters' keeps the counters and phases a
// program registers (openkal.prof), `perfmap' writes /tmp/perf-<pid>.map for a
// profiler of this system; a directory after `:' receives the report.
inline constexpr unsigned long kProfiledNames = 256;
bool profile_active();
bool profile_calls();
void record_call(unsigned long index, kal_u64 ns);
int  profile_counter(const char* name, kal_uintptr len, const volatile kal_u64* cell);
void profile_mark(const char* name, kal_uintptr len, int begin);
void profile_finish();
// An image's bytes, while they are at hand, for the symbols a measurement and
// openkal.debug name (`source' and `offset' say where they can be read again:
// a file the image is read from, at an offset; null for bytes that stay where
// they are --- an image a program carries).
void profile_loaded(const char* name, const void* bytes, kal_u64 size,
                    const char* source, kal_u64 offset);
void profile_settle();
kal_intptr symbolize(kal_uintptr address, char* out, kal_uintptr cap, kal_uintptr* start);
// A name as openkal names things: the supplied directory that is the longest
// prefix of it, and the rest (src/run.cpp).
bool locate_path(const char* path, kal_dir& dir, const char*& rest);
const binding* space_bindings(unsigned long& count);

inline bool same(const char* a, const char* b) {
    for (;; ++a, ++b) { if (*a != *b) return false; if (!*a) return true; }
}

}  // namespace okrun
