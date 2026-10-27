/* libokrun --- the runner's core: an image's names bound to this process's one
 * openkal implementation, its initialisers run, its entry entered (SPEC clause
 * 12.3). The program `okrun' and every self-contained program (M3) are this
 * library and a few lines. Prefix `okrun_'. */
#ifndef OKRUN_H
#define OKRUN_H

#ifdef __cplusplus
extern "C" {
#endif

struct okrun_options {
    /* Refuse an image that carries no signature, or one not made by a key in
     * `trusted' (32 bytes each) when `trusted_count' is not zero. */
    int                   require_signature;
    const unsigned char*  trusted;
    unsigned              trusted_count;
    /* Announce the image to a debugger (GDB JIT interface). */
    int                   debugger;
    /* The image is carried inside the program that runs it (a self-contained
     * program, M3): the image's own name (kal_env_image) is that program's,
     * and so is what starts the same program again. */
    int                   carried;
};

/* Runs an image that lies in memory. `name' is what the image is told its
 * own name is (`kal_env_image'); `argv' is what it is told its arguments are,
 * the first being its name as it was started. Bytes that are an archive of
 * images (an okb) are run as okrun_run_okb_bytes runs them, with okb.json's
 * entry. Returns only when the image could not be started, with a sentence in
 * `why'; the image's own end is the program's. */
int okrun_run_bytes(const void* bytes, unsigned long long size, const char* name,
                    int argc, const char* const* argv, const struct okrun_options* options,
                    char* why, unsigned long long why_cap);

/* The same, for an image or an okb named by a path the environment resolves.
 * The file is read once; an okb's members are used in place. */
int okrun_run_file(const char* path, int argc, const char* const* argv,
                   const struct okrun_options* options, char* why, unsigned long long why_cap);

/* --- archives and groups of images: run from memory (docs/okb.md) -------- */

/* Runs an image of an okb, or of any ZIP archive of images, that lies in
 * memory --- the bytes of a file read once, or the bytes a program carries.
 * Its members are used in place: each is stored, an image's bytes begin at a
 * multiple of 64 KiB, and its content is the one okb.json states (or, in an
 * archive without okb.json, the one its CRC-32 states); a member that is not
 * is refused, and nothing is copied out or written to disk.
 *
 * `entry' names the image to enter (`app.oke'); null takes the entry okb.json
 * states for this machine's architecture. A name is looked up in this
 * architecture's directory (okb.json's `dir', or the architecture's name),
 * then at the archive's root. The images the entry needs are found the same
 * way, then beside the program (`carried'), or beside argv[0], then in
 * `lib/<arch>/', `lib/' and each directory of OKRUN_PATH.
 *
 * With `require_signature' or trusted keys, okb.json must be signed (okb.sig)
 * by a trusted key and so must every image loaded from the archive. Returns
 * only when the image could not be started. */
int okrun_run_okb_bytes(const void* bytes, unsigned long long size, const char* entry,
                        int argc, const char* const* argv, const struct okrun_options* options,
                        char* why, unsigned long long why_cap);

/* An image of a group in memory: its name, as images that need it name it. */
struct okrun_image {
    const char*        name;
    const void*        bytes;
    unsigned long long size;
};

/* Runs `entry' of a group of images in memory, which resolve one another by
 * name before any file is searched. */
int okrun_run_images(const struct okrun_image* images, unsigned long count, const char* entry,
                     int argc, const char* const* argv, const struct okrun_options* options,
                     char* why, unsigned long long why_cap);

/* --- libraries: an image's exports called by a program of this system ----- */

/* An image (`.okso') loaded into this process, with the images it needs, bound
 * to this process's openkal and initialised. Its functions are in the image's
 * convention (System V on x86-64, whatever the system's). */
struct okrun_library;

/* `path' with a directory is opened as it is named; a bare name is searched
 * beside the program, in its `lib/<arch>/' and `lib/', and in OKRUN_PATH. The
 * library sees the program's own arguments and name. Null on failure, with a
 * sentence in `why'. */
struct okrun_library* okrun_open_library(const char* path, const struct okrun_options* options,
                                         char* why, unsigned long long why_cap);
struct okrun_library* okrun_open_library_bytes(const void* bytes, unsigned long long size,
                                               const char* name, const struct okrun_options* options,
                                               char* why, unsigned long long why_cap);
/* The address of a name the library exports, or null. */
void* okrun_symbol(struct okrun_library* library, const char* name);
/* Runs the library's finalisers and unloads it, and the images it needed that
 * nothing else holds. */
void  okrun_close(struct okrun_library* library);

/* The names this runner binds (the specification's surface), `count' of them. */
const char* const* okrun_names(unsigned long* count);

/* The address an image's import of `name' is bound to, in the image's
 * convention; null for a name this runner does not bind. */
void* okrun_resolve(const char* name);

#ifdef __cplusplus
}
#endif
#endif /* OKRUN_H */
