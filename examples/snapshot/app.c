/* A snapshot of an image's initialisers (openkal-image 0.4, docs/snapshot.md),
 * the image's own C library's part written out: the record `__okrun_snapshot'
 * and the second phase's entry `__okrun_snapshot_start'.
 *
 * Its initialiser obtains memory and fills it, records the context it runs on,
 * and reads a named value. A start from the snapshot finds the memory filled,
 * the context the snapshot's rather than its own, and its second phase
 * entered; a start without it runs the initialiser. Built as timed.c, the
 * initialiser also asks for the time, which a snapshot cannot hold. */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
typedef unsigned long long kal_u64;
typedef unsigned int kal_u32;
struct kal_stream { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
void* kal_alloc(kal_uintptr size, kal_uintptr align);
kal_uintptr kal_task_current(void);
kal_intptr kal_env_var(const char* name, kal_uintptr len, char* out, kal_uintptr cap);
kal_u64 kal_time_monotonic(void);

struct record { kal_u64 arena, size; kal_u32 phase, reserved; kal_u64 context; };
__attribute__((visibility("default"), used)) struct record __okrun_snapshot;

enum { kSize = 300000 };
static unsigned char* g_built;
static kal_uintptr g_context;
static kal_intptr g_named = -2;
static int g_second;
static kal_u64 g_seen;

static void put(const char* s) { kal_uintptr n = 0; while (s[n]) ++n; kal_stream_write(kal_stdout(), s, n); }

__attribute__((constructor)) static void build(void) {
    g_built = kal_alloc(kSize, 16);
    for (unsigned long i = 0; g_built && i < kSize; ++i) g_built[i] = (unsigned char)(i * 7 + 1);
    g_context = kal_task_current();
    char v[32];
    g_named = kal_env_var("OKIMG_SNAPSHOT_NAME", 19, v, sizeof v);
}

#ifdef ASKS_THE_TIME
__attribute__((constructor(200))) static void timed(void) { g_seen = kal_time_monotonic(); }
#endif

__attribute__((visibility("default"))) void __okrun_snapshot_start(void) {
    if (__okrun_snapshot.phase == 2) g_second = 1;
}

__attribute__((visibility("default"))) int ok_main(void) {
    int filled = g_built != 0;
    for (unsigned long i = 0; filled && i < kSize; ++i) filled = g_built[i] == (unsigned char)(i * 7 + 1);
    put(filled ? "snapshot: the memory is filled\n" : "snapshot: THE MEMORY IS WRONG\n");
    put(g_second && g_context != kal_task_current() ? "snapshot: started from the snapshot\n"
        : !g_second && g_context == kal_task_current() ? "snapshot: started by its initialisers\n"
        : "snapshot: THE PHASE AND THE CONTEXT DISAGREE\n");
    put(g_named >= 0 ? "snapshot: the name is set\n" : "snapshot: the name is absent\n");
    return 0;
}
