/* An image that starts a context in a copy of its own address space
 * (openkal.space, the call a library composes `fork' from), whose context
 * ends the copy with kal_exit (0.7.2, openkal-image#44). The copy holds the
 * runner's memory but not the runner's task that waits for the requests to
 * end; under 0.7.1 its kal_exit waited for that task to return, and the copy
 * never ended.
 *
 *   okrun forks.oke
 *       writes `forks: 7' when the copy ends with the status its context gave
 */
#include <openkal/abort.h>
#include <openkal/process.h>
#include <openkal/space.h>
#include <openkal/stream.h>

static kal_uintptr length(const char* s) { kal_uintptr n = 0; while (s[n]) ++n; return n; }
static void say(const char* s) { kal_stream_write(kal_stdout(), s, length(s)); }
static void number(int v) {
    char d[16]; int n = 0;
    unsigned u = v < 0 ? (unsigned)-v : (unsigned)v;
    do { d[n++] = (char)('0' + u % 10); u /= 10; } while (u);
    if (v < 0) say("-");
    char out[16]; int k = 0;
    while (n) out[k++] = d[--n];
    out[k] = 0;
    say(out);
}

/* The copy's stack: the caller's to provide (openkal/space.h), aligned as a
 * call's is on every architecture an image is built for. */
static unsigned char stack[64 * 1024] __attribute__((aligned(16)));

/* Where the copy's context begins. Nothing lies beneath it, so it ends the copy
 * rather than returning. */
static void copy(void* arg) {
    (void)arg;
    kal_exit(7);
}

int ok_main(void) {
    struct kal_process p;
    const int rc = kal_space_start(&copy, 0, stack + sizeof stack, &p);
    if (rc != kal_ok) {
        say("forks: not started ");
        number(rc);
        say("\n");
        return 2;
    }
    int status = 0, terminated = 0;
    if (kal_process_wait(p, &status, &terminated) != kal_ok) {
        say("forks: not waited for\n");
        return 3;
    }
    say("forks: ");
    number(terminated ? -1 : status);
    say("\n");
    return 0;
}
