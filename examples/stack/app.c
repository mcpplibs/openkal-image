/* The image's main thread has the stack a thread has (openkal-image 0.5.2): an
 * image is entered on the runner's main thread, and on Windows that thread's
 * stack is the runner's reservation. This one recurses through 6 MiB of
 * frames, each touched page by page (-fstack-clash-protection), where a thread
 * of openkal-windows has at least 8 MiB and Linux and macOS give the main
 * thread 8 MiB. The entry is `int ok_main(void)' (SPEC 12.2). */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
struct kal_stream { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);

static void put(const char* s) {
    unsigned long n = 0; while (s[n]) ++n;
    kal_stream_write(kal_stdout(), s, n);
}

__attribute__((noinline)) static unsigned descend(unsigned depth) {
    volatile unsigned char frame[64 * 1024];
    for (unsigned i = 0; i < sizeof frame; i += 4096) frame[i] = (unsigned char)depth;
    unsigned below = depth ? descend(depth - 1) : 0;
    return below + frame[depth % sizeof frame];
}

__attribute__((visibility("default"))) int ok_main(void) {
    descend(96);   /* 96 frames of 64 KiB: 6 MiB */
    put("stack: 6 MiB on the main thread\n");
    return 0;
}
