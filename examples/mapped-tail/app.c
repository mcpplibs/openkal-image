/* A touched read-only segment whose final run is shorter than Windows' file
 * view alignment. A refused tail must not recopy earlier read-only views. */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
struct kal_stream { kal_uintptr h; };
struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
static const unsigned char bytes[2 * 65536 + 123] = {42, [2 * 65536 + 122] = 17};
__attribute__((visibility("default"))) int ok_main(void) {
    const volatile unsigned char* p = bytes;
    unsigned sum = 0;
    for (unsigned i = 0; i < sizeof bytes; ++i) sum += p[i];
    const char message[] = "mapped tail: bytes intact\n";
    if (sum != 59) return 1;
    kal_stream_write(kal_stdout(), message, sizeof message - 1);
    return 0;
}
