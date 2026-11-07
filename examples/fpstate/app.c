/* The image is entered in its convention's floating-point state (SPEC 12.2,
 * openkal-image 0.5.3): on x86-64 the x87 control word 0x037F and MXCSR
 * 0x1F80, on AArch64 FPCR zero --- at its entry and in each context it starts.
 * Windows starts a thread with the x87 at double precision (0x027F), under
 * which a C library that computes in long double reads "0.4" as
 * 0x1.99999999998p-2. The entry is `int ok_main(void)' (SPEC 12.2). */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
struct kal_stream { kal_uintptr h; };
struct kal_task { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
int kal_task_start(void (*entry)(void*), void* arg, struct kal_task* out);
int kal_task_join(struct kal_task);

static void put(const char* s) {
    unsigned long n = 0; while (s[n]) ++n;
    kal_stream_write(kal_stdout(), s, n);
}

/* Non-zero where the state is the convention's. */
static int conventional(void) {
#if defined(__x86_64__)
    unsigned short x87; unsigned mxcsr;
    __asm__ volatile("fnstcw %0\n\tstmxcsr %1" : "=m"(x87), "=m"(mxcsr));
    return x87 == 0x037F && (mxcsr & 0xFFC0) == 0x1F80;
#elif defined(__aarch64__)
    unsigned long fpcr;
    __asm__ volatile("mrs %0, fpcr" : "=r"(fpcr));
    return fpcr == 0;
#else
    return 1;
#endif
}

static void context(void* seen) { *(int*)seen = conventional(); }

__attribute__((visibility("default"))) int ok_main(void) {
    int at_entry = conventional(), in_context = 0;
    struct kal_task t;
    if (kal_task_start(context, &in_context, &t) == 0) kal_task_join(t);
    put(at_entry ? "fp: the convention's at the entry" : "fp: another at the entry");
    put(in_context ? ", the convention's in a context\n" : ", another in a context\n");
    return at_entry && in_context ? 0 : 3;
}
