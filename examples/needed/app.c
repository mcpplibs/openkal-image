/* An image that needs another (DT_NEEDED liboktwice.okso) and calls into it. */
typedef unsigned long kal_uintptr; typedef long kal_intptr;
struct kal_stream { kal_uintptr h; };
struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
long twice(long);
long next_value(void);
static void put(const char* s) { kal_uintptr n = 0; while (s[n]) ++n; kal_stream_write(kal_stdout(), s, n); }
__attribute__((visibility("default"))) int ok_main(void) {
    const long a = twice(21), b = next_value();
    put(a == 42 && b == 41 ? "needed: twice(21) = 42, next_value() = 41\n" : "needed: WRONG\n");
    return a == 42 && b == 41 ? 0 : 1;
}
