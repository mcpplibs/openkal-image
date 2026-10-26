/* A weak import: an image that uses an interface where it is provided and
 * runs without it where it is not. `kal_net_listen_at' is imported weakly, so
 * the image requires openkal.stream and openkal.env and not openkal.net (SPEC
 * 12.4): the loader binds the name when the implementation provides it and
 * leaves it zero otherwise. The entry is `int ok_main(void)' (SPEC 12.2). */
typedef unsigned long kal_uintptr;
typedef long kal_intptr;
struct kal_stream { kal_uintptr h; };
struct kal_dir { kal_uintptr h; };

struct kal_stream kal_stdout(void);
kal_intptr kal_stream_write(struct kal_stream, const void*, kal_uintptr);
kal_uintptr kal_env_arg_count(void);
__attribute__((weak)) int kal_net_listen_at(struct kal_dir, const char*, kal_uintptr, void*);

static void put(const char* s) {
    unsigned long n = 0; while (s[n]) ++n;
    kal_stream_write(kal_stdout(), s, n);
}

__attribute__((visibility("default"))) int ok_main(void) {
    put(kal_env_arg_count() > 0 ? "weak: arguments seen\n" : "weak: no arguments\n");
    put(kal_net_listen_at ? "weak: openkal.net bound\n" : "weak: openkal.net absent\n");
    return 0;
}
