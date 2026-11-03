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
bool profile_samples();   // `samples': this runner takes them (0.4)
bool profile_touches();   // `touch': this runner records them (0.4)
// The phases of a start (0.4, `phases'): each mark is a moment of the start ---
// admitted, loaded, a snapshot mapped, initialised, main returned --- with the
// time and the page faults so far.
void profile_phase(const char* name);
// What the runner chose at a point a resource is spent (0.4): the placement's
// data, the snapshot, what is read ahead.
void profile_note(const char* point, const char* outcome, kal_u64 bytes);
// What a measurement takes once the image is loaded and before it runs: the
// samples begun, the touches of its executable parts begun (`okld_iterate').
void profile_begin_run();
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
// openkal.space's word of properties and its binding where it is bound; zero
// and null where it is not (src/bindings_space.cpp, src/no_space.cpp).
kal_uintptr space_props();
void* space_props_binding();
// The word of interfaces an image is told: the implementation's, and the
// loader's own (openkal.prof, openkal.debug; SPEC 12.3).
kal_u64 own_interfaces();

// --- a snapshot of an image's initialisers (0.4, src/seal.cpp) ---------------
//
// The bindings while they run: memory from an arena above the image's end
// (`seal_begin'), the implementation's facts, `kSealContext' as the one
// context, and every other name a refusal, which ends the runner making the
// snapshot with the name it was asked (`seal_refused', src/run.cpp).
inline constexpr kal_uintptr kSealContext = static_cast<kal_uintptr>(0x5ea1ed0000000001ull);
[[noreturn]] void seal_refused(const char* what);
void    seal_begin(kal_u64 image_end);
// The arena's addresses, [lo, hi): all the environment gave it.
void    seal_arena(kal_u64& lo, kal_u64& hi);
void*   seal_resolve(const char* name);
// Whether a word is the address of one of the bindings above.
bool    seal_is_binding(kal_uintptr word);
// Which of a start's own answers the initialisers asked for, and what the
// implementation states of itself with those answers, as one word a snapshot
// records.
kal_u64 seal_asked();
kal_u32 environment_facts(kal_u64 asked);
// The named values the initialisers asked for, with a word of each answer, as
// bytes kept with the snapshot (`out' null: their size); and whether this start
// answers each the same.
kal_u64 seal_kept(void* out, kal_u64 cap);
bool    seal_kept_holds(const void* kept, kal_u64 size);

inline bool same(const char* a, const char* b) {
    for (;; ++a, ++b) { if (*a != *b) return false; if (!*a) return true; }
}

}  // namespace okrun
