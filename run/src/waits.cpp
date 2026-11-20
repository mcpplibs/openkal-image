// THE CALL EACH TASK OF THE IMAGE WAITS IN, WRITTEN WHEN THE PROGRAM IS ASKED TO
// END (0.7). A harness whose time runs out first asks the program to end and
// waits a while before it ends it by force (mcpp design 2026-11-19 §12): a
// program ended by force leaves nothing to say what it was waiting for, and a
// task of an image that never returns is in a call of openkal or in its own
// code. Both runners' (0.6.3).
//
// WHERE THE IMAGE IS ENTERED THE RUNNER TAKES THE REQUESTS (`watch_requests'):
// a task of its own asks for the word (`kal_process_stop_requested') and waits
// upon it. Each task of the image has a line --- its identity
// (`kal_task_current') and the call that waits it is in --- taken as the task
// begins (bindings.cpp, `enter_image'; the entering task here) and kept by the
// entry of each call that waits (build.mcpp's `waits'). A request writes one
// line per task to the error stream, then is acted on as it was before the
// runner took it: the program ends as the request would have ended it
// (`kal_process_end_as_requested'), unless the image took the requests over
// itself (`requests_taken'). Such an image is given a word of the runner's,
// counted as the implementation counts its own once the record is written: on
// the implementation's word the image woke with the runner's task and could end
// the program before the record was written (measured: it ended first, and no
// record was written).
//
// A TABLE KEYED BY THE TASK'S IDENTITY, as prof.cpp keeps its phases, rather
// than thread-local storage: this library may be linked into a program that
// brings no C++ run-time, and whether a context has the toolchain's
// thread-local storage is a property an implementation states
// (KAL_TASK_PROP_THREAD_LOCAL). Only a call that waits looks its line up, so a
// call that returns at once pays nothing; the shortest call that waits pays
// some ten nanoseconds (measured on Linux x86-64: a write of one byte to the
// null device took 95 ns where it took 85, a wait upon a word that differed
// 121 ns where it took 120).
//
// Where the implementation reports no request (its word is null) or no task can
// be started to wait for one, nothing is taken: a request ends the program as
// before, without the lines, and a measurement's report says why (`requests').
//
// THE REQUESTS ARE TAKEN ONCE THE IMAGE IS LOADED, AND THE RUNNER'S TASK RETURNS
// BEFORE THE RUNNER ENDS THE PROGRAM (0.7.1). A start that is refused returns
// with the program's requests as they were, which a program of the system that
// runs images through libokrun keeps. Where the image's main returns, and where
// the image calls `kal_exit', the runner asks its task to return and joins it
// (`stop_watching'): the program ends as the image ends it, with the image's
// tasks alone. A debugger that resumes each task in turn otherwise found the
// runner's gone with the program the image had ended (measured: GDB 15,
// continuing from a stop in a one-task image to its end, stopped with
// "Couldn't get registers: No such process" in 10 of 12 runs of 0.7.0;
// tools/tests/debugger_end.py).
//
// A COPY OF THE PROGRAM HAS NO TASK OF THE RUNNER'S (0.7.2, openkal-image#44). A
// library composes `fork' by starting a context in a copy of the address space
// (openkal.space): the copy holds this memory, the runner's task among what it
// records, and not the task, which belongs to the program that was copied.
// There nothing returns and nothing is joined, and the image's requests to end
// are its own (`in_watching_program'). Under 0.7.1 the copy's `kal_exit'
// waited for the task's return without end, and a program that started another
// by fork and exec never ended (measured in Sunrisepeak/cmd#5).
#include <openkal.h>
#include "runner.h"

namespace okrun {

#if OKRUN_HAS_PROCESS && OKRUN_HAS_TASK

struct task_line {
    kal_uintptr   task;   // the identity; zero: free
    unsigned long call;   // the call's position among the bound names, one more; zero: none
};

namespace {

// As many tasks as prof.cpp keeps phases for. A line is taken within kReach of
// the slot its identity hashes to, and found there.
constexpr unsigned kLines = 512;
constexpr unsigned kReach = 16;
task_line g_lines[kLines];
// The line of a task that found none free within its reach: counted while it
// runs, so that the record says how many tasks it could not name.
task_line g_no_line;
unsigned g_unheld = 0;
int g_watched = 0;        // a task of the runner's waits for the requests
int g_taken = 0;          // the image took them over
kal_u32 g_image_word = 0; // and was given this word
kal_uintptr g_entered = 0;   // the task that entered the image
// The runner's task, until it is joined where the program ends (0.7.1): asked
// to return (`g_ending'), it says it has (`g_returned'); the implementation's
// word it waits upon is `g_word' once it has asked for it.
kal_task g_watcher{};
int g_running = 0;
int g_ending = 0;
kal_u32 g_returned = 0;
const kal_u32* g_word = nullptr;
// The program the runner's task belongs to, as the implementation identifies
// it; zero where it gave no identity.
kal_u64 g_watching_program = 0;

// This program's identity: read again at each call, since a copy of the
// program holds the value the program it copies read.
kal_u64 this_program() {
    kal_process self{};
    if (kal_process_self(&self) != kal_ok) return 0;
    kal_program_info info{};
    info.self_size = sizeof info;
    const int rc = kal_process_info(self, KAL_PINFO_ID, &info);
    kal_process_close(self);
    return rc == kal_ok && (info.present & KAL_PINFO_ID) ? info.id : 0;
}

// Whether the runner's task is in this program. An identity either side could
// not read leaves the answer it had before 0.7.2: it is.
bool in_watching_program() {
    const kal_u64 watching = __atomic_load_n(&g_watching_program, __ATOMIC_ACQUIRE);
    if (watching == 0) return true;
    const kal_u64 here = this_program();
    return here == 0 || here == watching;
}

unsigned home(kal_uintptr task) {
    return static_cast<unsigned>((static_cast<kal_u64>(task) * 0x9E3779B97F4A7C15ull) >> 40) % kLines;
}

task_line* find(kal_uintptr task) {
    const unsigned h = home(task);
    for (unsigned k = 0; k < kReach; ++k) {
        task_line& l = g_lines[(h + k) % kLines];
        if (__atomic_load_n(&l.task, __ATOMIC_ACQUIRE) == task) return &l;
    }
    return nullptr;
}

task_line* take(kal_uintptr task) {
    const unsigned h = home(task);
    for (unsigned k = 0; k < kReach; ++k) {
        task_line& l = g_lines[(h + k) % kLines];
        kal_uintptr none = 0;
        if (__atomic_compare_exchange_n(&l.task, &none, task, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return &l;
    }
    return nullptr;
}

// --- the record ----------------------------------------------------------------------------------

// A standard error whose reader has stopped reading would hold the record, and
// with it the program the request would have ended; a write is bounded where
// the implementation bounds one (openkal.timeout, a second), and what it cannot
// write in the bound is left unwritten.
void say(const char* s, kal_uintptr n) {
    const kal_stream err = kal_stderr();
#if OKRUN_HAS_TIMEOUT
    if (kal_timeout_write(err, s, n, 1000000000ull) != -static_cast<kal_intptr>(kal_err_not_supported)) return;
#endif
    kal_stream_write(err, s, n);
}

char g_out[4096];
kal_uintptr g_at = 0;
void flush() { if (g_at) say(g_out, g_at); g_at = 0; }
void put(const char* s) {
    for (; *s; ++s) {
        if (g_at == sizeof g_out) flush();
        g_out[g_at++] = *s;
    }
}
void put_number(kal_u64 v) {
    char d[24];
    int n = 0;
    do { d[n++] = static_cast<char>('0' + v % 10); v /= 10; } while (v);
    char o[24];
    int k = 0;
    while (n) o[k++] = d[--n];
    o[k] = 0;
    put(o);
}

void put_line(kal_uintptr task, unsigned long call, const binding* names, unsigned long count) {
    put("okrun:   task ");
    put_number(task);
    if (task == g_entered) put(" (main)");
    put(": ");
    put(call && call <= count ? names[call - 1].name : "in no call that waits");
    put("\n");
}

void write_record() {
    unsigned long count = 0;
    const binding* names = bindings(count);
    put("okrun: asked to end; the openkal call each task of the image waits in:\n");
    if (const task_line* m = find(g_entered)) put_line(g_entered, __atomic_load_n(&m->call, __ATOMIC_ACQUIRE), names, count);
    for (const task_line& l : g_lines) {
        const kal_uintptr task = __atomic_load_n(&l.task, __ATOMIC_ACQUIRE);
        if (task && task != g_entered) put_line(task, __atomic_load_n(&l.call, __ATOMIC_ACQUIRE), names, count);
    }
    if (const unsigned n = __atomic_load_n(&g_unheld, __ATOMIC_ACQUIRE)) {
        put("okrun:   and ");
        put_number(n);
        put(" task(s) more, for which the record has no line\n");
    }
    flush();
}

// --- the task that waits for the requests --------------------------------------------------------

// The requests, given to an image that took them over: each counted, zero
// skipped where the count wraps (openkal 0.25), and every task that waits upon
// the word woken.
void deliver(kal_u32 requests) {
    kal_u32 next = __atomic_load_n(&g_image_word, __ATOMIC_RELAXED) + requests;
    if (next == 0) next = 1;
    __atomic_store_n(&g_image_word, next, __ATOMIC_RELEASE);
    kal_task_wake(&g_image_word, 0x7fffffff, nullptr);
}

void wait_for_requests() {
    const kal_u32* word = kal_process_stop_requested();
    if (!word) {
        __atomic_store_n(&g_watched, 0, __ATOMIC_RELEASE);
        profile_note("requests", "not taken: the implementation reports no request to end", 0);
        return;
    }
    __atomic_store_n(&g_word, word, __ATOMIC_RELEASE);
    profile_note("requests", "taken: a request writes the call each task waits in", 0);
    kal_u32 seen = 0;
    for (;;) {
        // The program ends as the image ended it: a request that comes now is
        // not acted on.
        if (__atomic_load_n(&g_ending, __ATOMIC_ACQUIRE)) return;
        const kal_u32 now = __atomic_load_n(word, __ATOMIC_ACQUIRE);
        if (now == seen) {
            // A wait that fails is tried again a little later, rather than at once and for ever.
            if (kal_task_wait(word, now, 0) != kal_ok) kal_time_sleep(10000000ull);
            continue;
        }
        const kal_u32 requests = now - seen;
        seen = now;
        write_record();
        if (__atomic_load_n(&g_taken, __ATOMIC_ACQUIRE)) {
            deliver(requests);
            continue;
        }
        kal_process_end_as_requested();
        // It returns only where the program has not been asked to end, and it has.
        static const char why[] = "okrun: asked to end, and kal_process_end_as_requested returned";
        kal_abort(why, sizeof why - 1);
    }
}

void watch(void*) {
    wait_for_requests();
    __atomic_store_n(&g_returned, 1u, __ATOMIC_RELEASE);
    kal_task_wake(&g_returned, 1, nullptr);
}

}  // namespace

void watch_requests() {
    g_entered = kal_task_current();
    take(g_entered);
    __atomic_store_n(&g_watching_program, this_program(), __ATOMIC_RELEASE);
    __atomic_store_n(&g_watched, 1, __ATOMIC_RELEASE);
    if (kal_task_start(&watch, nullptr, &g_watcher) == kal_ok) {
        __atomic_store_n(&g_running, 1, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&g_watched, 0, __ATOMIC_RELEASE);
    profile_note("requests", "not taken: no task could be started to wait for them", 0);
}

void stop_watching() {
    if (!__atomic_exchange_n(&g_running, 0, __ATOMIC_ACQ_REL)) return;
    // In a copy of the program no task of the runner's will return (0.7.2).
    if (!in_watching_program()) return;
    __atomic_store_n(&g_ending, 1, __ATOMIC_RELEASE);
    // A wake that comes between the task's look at `g_ending' and its wait is
    // not seen; the next, a millisecond on, is. The word is the
    // implementation's, and a context that waits upon a word looks at it again
    // when woken, so a wake that is no request changes nothing for another.
    while (!__atomic_load_n(&g_returned, __ATOMIC_ACQUIRE)) {
        if (const kal_u32* word = __atomic_load_n(&g_word, __ATOMIC_ACQUIRE)) kal_task_wake(word, 0x7fffffff, nullptr);
        kal_task_wait(&g_returned, 0u, 1000000ull);
    }
    kal_task_join(g_watcher);
}

task_line* task_begin() {
    if (!__atomic_load_n(&g_watched, __ATOMIC_ACQUIRE)) return nullptr;
    if (task_line* l = take(kal_task_current())) return l;
    __atomic_add_fetch(&g_unheld, 1u, __ATOMIC_RELAXED);
    return &g_no_line;
}

void task_end(task_line* line) {
    if (line == &g_no_line) {
        __atomic_sub_fetch(&g_unheld, 1u, __ATOMIC_RELAXED);
        return;
    }
    if (!line) return;
    __atomic_store_n(&line->call, 0ul, __ATOMIC_RELAXED);
    __atomic_store_n(&line->task, kal_uintptr{0}, __ATOMIC_RELEASE);
}

task_line* wait_begin(unsigned long index) {
    if (!__atomic_load_n(&g_watched, __ATOMIC_RELAXED)) return nullptr;
    task_line* l = find(kal_task_current());
    if (l) __atomic_store_n(&l->call, index + 1, __ATOMIC_RELEASE);
    return l;
}

void wait_end(task_line* line) {
    if (line) __atomic_store_n(&line->call, 0ul, __ATOMIC_RELEASE);
}

const kal_u32* requests_taken() {
    // Taken now, as the image's own call would have taken them, whether or not
    // the runner's task has yet; a request is then counted, and its record
    // written, whichever asked first.
    const kal_u32* word = kal_process_stop_requested();
    if (!word || !__atomic_load_n(&g_watched, __ATOMIC_ACQUIRE)) return word;
    // A copy of the program has no task of the runner's to count a request on
    // the image's word: its requests are its own (0.7.2).
    if (!in_watching_program()) return word;
    __atomic_store_n(&g_taken, 1, __ATOMIC_RELEASE);
    return &g_image_word;
}

#else

// Without processes or contexts there is no task to wait for a request: an
// image that asks for the requests is given the implementation's word.
struct task_line {};
void watch_requests() {}
void stop_watching() {}
task_line* task_begin() { return nullptr; }
void task_end(task_line*) {}
task_line* wait_begin(unsigned long) { return nullptr; }
void wait_end(task_line*) {}
#if OKRUN_HAS_PROCESS
const kal_u32* requests_taken() { return kal_process_stop_requested(); }
#endif

#endif

}  // namespace okrun
