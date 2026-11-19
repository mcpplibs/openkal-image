/* An image asked to end while its tasks wait (openkal-image 0.7.0). Its main
 * task starts another, which waits upon a word nobody changes, and joins it;
 * once the other has begun, the image says which task is which. okrun, asked to
 * end, writes the call each task waits in --- the main task kal_task_join, the
 * other kal_task_wait --- and ends the program as the request would have ended
 * it.
 *
 * With the argument `takes', the image first takes the requests to end over
 * (kal_process_stop_requested): the other task sleeps, the main task waits upon
 * the request word, and once asked the image says so and returns 7. okrun
 * writes the record --- kal_task_wait and kal_time_sleep --- and leaves the
 * request to the image. tools/tests/end_request.py asks and reads both. */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
typedef unsigned int kal_u32;
typedef unsigned long long kal_u64;
struct kal_stream { kal_uintptr h; };
struct kal_task { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
kal_uintptr kal_env_arg_count(void);
kal_intptr kal_env_arg(kal_uintptr, char*, kal_uintptr);
int kal_task_start(void (*entry)(void*), void* arg, struct kal_task* out);
int kal_task_join(struct kal_task);
kal_uintptr kal_task_current(void);
int kal_task_wait(const kal_u32* word, kal_u32 expected, kal_u64 timeout_ns);
int kal_task_wake(const kal_u32* word, kal_uintptr count, kal_uintptr* woken);
void kal_time_sleep(kal_u64 ns);
const kal_u32* kal_process_stop_requested(void);

static void put(const char* s) {
    unsigned long n = 0; while (s[n]) ++n;
    kal_stream_write(kal_stdout(), s, n);
}
static void put_num(kal_uintptr v) {
    char b[24]; int i = 23; b[i] = 0;
    do { b[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    put(b + i);
}

static kal_uintptr g_other;
static kal_u32 g_begun;
static kal_u32 g_never;

static void begun(void) {
    g_other = kal_task_current();
    __atomic_store_n(&g_begun, 1, __ATOMIC_RELEASE);
    kal_task_wake(&g_begun, 1, 0);
}
static void waits(void* arg) {
    (void)arg;
    begun();
    for (;;) kal_task_wait(&g_never, 0, 0);
}
static void sleeps(void* arg) {
    (void)arg;
    begun();
    for (;;) kal_time_sleep(3600ull * 1000000000ull);
}

static int takes(void) {
    char a[8];
    if (kal_env_arg_count() < 2) return 0;
    const kal_intptr n = kal_env_arg(1, a, sizeof a);
    return n == 5 && a[0] == 't' && a[1] == 'a' && a[2] == 'k' && a[3] == 'e' && a[4] == 's';
}

__attribute__((visibility("default"))) int ok_main(void) {
    const int taken = takes();
    const kal_u32* stop = 0;
    if (taken && !(stop = kal_process_stop_requested())) { put("ending: no request reaches this program\n"); return 3; }
    struct kal_task other;
    if (kal_task_start(taken ? sleeps : waits, 0, &other) != 0) { put("ending: no task\n"); return 3; }
    while (__atomic_load_n(&g_begun, __ATOMIC_ACQUIRE) == 0) kal_task_wait(&g_begun, 0, 0);
    put("ending: main "); put_num(kal_task_current()); put(", other "); put_num(g_other); put("\n");
    if (!taken) {
        kal_task_join(other);
        return 0;
    }
    while (__atomic_load_n(stop, __ATOMIC_ACQUIRE) == 0) kal_task_wait(stop, 0, 0);
    put("ending: asked to end, and the image ends by itself\n");
    return 7;
}
