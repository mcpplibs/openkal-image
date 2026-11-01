/* What a program states to a measurement, and the name of one of its own
 * addresses (openkal.prof and openkal.debug, a loader's interfaces, SPEC 12.3;
 * openkal-image 0.2). The image registers a counter, counts into it, marks a
 * phase twice, and asks the loader for the name of a function of its own, which
 * the loader reads from the image's symbol table --- a table loading never
 * places in memory. The entry is `int ok_main(void)' (SPEC 12.2). */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
typedef unsigned long long kal_u64;
struct kal_stream { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
int  kal_prof_active(void);
int  kal_prof_counter(const char* name, kal_uintptr len, const volatile kal_u64* cell);
void kal_prof_mark(const char* name, kal_uintptr len, int begin);
kal_intptr kal_debug_symbolize(kal_uintptr address, char* out, kal_uintptr cap, kal_uintptr* start);

static void put(const char* s, kal_uintptr n) { kal_stream_write(kal_stdout(), s, n); }
static void say(const char* s) { kal_uintptr n = 0; while (s[n]) ++n; put(s, n); }

static volatile kal_u64 widgets;

__attribute__((noinline, visibility("default"))) int prof_named_function(int x) { return x * 7 + 3; }

__attribute__((visibility("default"))) int ok_main(void) {
    say(kal_prof_active() ? "prof: measured\n" : "prof: not measured\n");
    kal_prof_counter("example.widgets", 15, &widgets);
    for (int round = 0; round < 2; ++round) {
        kal_prof_mark("example.phase", 13, 1);
        for (int i = 0; i < 21; ++i) widgets = widgets + 1;
        kal_prof_mark("example.phase", 13, 0);
    }
    char name[128];
    kal_uintptr start = 0;
    int (*volatile fn)(int) = &prof_named_function;
    const kal_intptr n = kal_debug_symbolize((kal_uintptr)fn + 1, name, sizeof name, &start);
    if (n > 0 && n < (kal_intptr)sizeof name) { say("debug: "); put(name, (kal_uintptr)n); say("\n"); }
    else say("debug: no name\n");
    return prof_named_function(0) == 3 ? 0 : 1;
}
