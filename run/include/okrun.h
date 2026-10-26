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
};

/* Runs an image that lies in memory. `name' is what the image is told its
 * own name is (`kal_env_image'); `argv' is what it is told its arguments are,
 * the first being its name as it was started. Returns only when the image
 * could not be started, with a sentence in `why'; the image's own end is the
 * program's. */
int okrun_run_bytes(const void* bytes, unsigned long long size, const char* name,
                    int argc, const char* const* argv, const struct okrun_options* options,
                    char* why, unsigned long long why_cap);

/* The same, for an image named by a path the environment resolves. */
int okrun_run_file(const char* path, int argc, const char* const* argv,
                   const struct okrun_options* options, char* why, unsigned long long why_cap);

/* The names this runner binds (the specification's surface), `count' of them. */
const char* const* okrun_names(unsigned long* count);

/* The address an image's import of `name' is bound to, in the image's
 * convention; null for a name this runner does not bind. */
void* okrun_resolve(const char* name);

#ifdef __cplusplus
}
#endif
#endif /* OKRUN_H */
