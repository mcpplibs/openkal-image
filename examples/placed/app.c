/* An image at its base (openkal 0.23, SPEC 12.3 and 12.4, type 3).
 *
 * Its read-only-after-relocation data holds addresses: of its own text, which
 * relative relocations compute (a table of 128 KiB, so that whole 64 KiB blocks
 * of it are the file's pages where the implementation maps files), and of an
 * implementation's entry, which a relocation naming a symbol computes. Its
 * writable data holds addresses and is written. What it prints is the same
 * wherever it is placed; the base it reports is the one `okld inspect' states
 * when okrun places it there. */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
struct kal_stream { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);

void* memcpy(void* d, const void* s, unsigned long n) {
    unsigned char* a = d; const unsigned char* b = s;
    while (n--) *a++ = *b++;
    return d;
}
void* memset(void* d, int c, unsigned long n) {
    unsigned char* a = d;
    while (n--) *a++ = (unsigned char)c;
    return d;
}

extern const char __ehdr_start[] __attribute__((visibility("hidden")));

static const char text[] = "placed";
static const char* const many[16384] = { [0 ... 16383] = text };
static kal_intptr (*const write_to)(struct kal_stream, const void*, kal_uintptr) = kal_stream_write;
static const char* chosen[2] = { "one", "two" };

static unsigned long len(const char* s) { unsigned long n = 0; while (s[n]) ++n; return n; }
static void put(const char* s) { write_to(kal_stdout(), s, len(s)); }
static void put_hex(kal_uintptr v) {
    char b[19]; int i = 18; b[i] = 0;
    do { b[--i] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
    b[--i] = 'x'; b[--i] = '0';
    put(b + i);
}

int ok_main(void) {
    unsigned long same = 0;
    for (unsigned long i = 0; i < sizeof many / sizeof many[0]; ++i)
        if (many[i] == text) ++same;
    put(same == sizeof many / sizeof many[0] ? "placed: the table holds its text\n" : "placed: THE TABLE IS WRONG\n");
    put(write_to == kal_stream_write ? "placed: the entry is the implementation's\n" : "placed: THE ENTRY IS WRONG\n");
    const char* was = chosen[0];
    chosen[0] = chosen[1];
    chosen[1] = was;
    put("placed: written ");
    put(chosen[0]);
    put(" ");
    put(chosen[1]);
    put("\nbase ");
    put_hex((kal_uintptr)__ehdr_start);
    put("\n");
    return 0;
}
