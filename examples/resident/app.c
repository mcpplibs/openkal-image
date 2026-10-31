/* What stays resident once an image is loaded: 8 MiB of the file's bytes in a
 * segment (a constant array with an initialiser is in the file, zeros
 * included), read whole, then two seconds' sleep in which CI reads the
 * process's mappings. The runner releases the file it ran once the image is
 * placed (openkal-image 0.1.6), so neither the image nor the okb is mapped
 * while the image runs; the segment's copy is. The entry is `int
 * ok_main(void)' (SPEC 12.2). */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
typedef unsigned long long kal_u64;
struct kal_stream { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
void kal_time_sleep(kal_u64 ns);

static const unsigned char blob[8u << 20] = { 1 };

static void put(const char* s) {
    unsigned long n = 0; while (s[n]) ++n;
    kal_stream_write(kal_stdout(), s, n);
}

__attribute__((visibility("default"))) int ok_main(void) {
    volatile unsigned sum = 0;
    for (unsigned long i = 0; i < sizeof blob; i += 4096) sum += blob[i];
    put(sum == 1 ? "resident: loaded\n" : "resident: not its bytes\n");
    kal_time_sleep(2000000000ull);
    return 0;
}
