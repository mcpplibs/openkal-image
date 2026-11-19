/* An image that starts images (0.7.1): itself, by the name its runner states
 * for it (kal_env_image), and the image `exits.oke' beside it, each started as
 * any program is (kal_process_spawn). The runner enters each through its
 * loader, and each observes the vector its starter gave (openkal clause 7.6).
 *
 *   okrun starts.oke [<program> <argument>...]
 *       starts itself, then exits.oke, then the program of the system named,
 *       whose status is expected to be 5; writes `starts: ok' when all three
 *       end as expected
 *   okrun-host file starts.oke refused
 *       run where no loader is named: a start of an image file is refused as
 *       kal_err_not_program, and nothing is started
 *
 * Started as `as-started child', it exits with 7 where its first argument is
 * the one its starter gave, and with 8 otherwise.
 */
#include <openkal/env.h>
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/stream.h>

static kal_uintptr length(const char* s) { kal_uintptr n = 0; while (s[n]) ++n; return n; }
static void say(const char* s) { kal_stream_write(kal_stdout(), s, length(s)); }
static int same(const char* a, const char* b) {
    for (;; ++a, ++b) { if (*a != *b) return 0; if (!*a) return 1; }
}
static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }
static int separator(char c) { return c == '/' || c == '\\'; }
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

/* The supplied directory whose name is the longest prefix of `name', and the
 * rest, as a program of this interface names a file by an absolute name. */
static int locate(const char* name, struct kal_dir* dir, const char** rest) {
    kal_uintptr best = 0;
    int found = 0;
    for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
        struct kal_dir d; char pname[1024]; kal_uintptr len = 0;
        if (kal_fs_preopen(i, &d, pname, sizeof pname, &len) != kal_ok || len == 0 || len >= sizeof pname) continue;
        kal_uintptr k = 0;
        while (k < len && name[k] && (lower(name[k]) == lower(pname[k]) || (separator(name[k]) && separator(pname[k])))) ++k;
        if (k != len) continue;
        if (!separator(pname[len - 1]) && name[len] && !separator(name[len])) continue;
        if (found && len <= best) continue;
        best = len; found = 1; *dir = d;
    }
    if (!found) return 0;
    *rest = name + best;
    while (separator(**rest)) ++*rest;
    return 1;
}

/* This program's environment, as `NAME=value' entries. */
static char env_text[32768];
static const char* env[256];
static kal_uintptr env_lens[256];
static kal_uintptr env_count;
static void take_environment(void) {
    kal_uintptr at = 0;
    for (kal_uintptr i = 0; i < kal_env_var_count() && env_count < 256; ++i) {
        char name[256];
        const kal_intptr n = kal_env_var_at(i, name, sizeof name);
        if (n <= 0 || n >= (kal_intptr)sizeof name) continue;
        if (at + (kal_uintptr)n + 1 >= sizeof env_text) break;
        char* entry = env_text + at;
        for (kal_intptr k = 0; k < n; ++k) entry[k] = name[k];
        entry[n] = '=';
        const kal_intptr v = kal_env_var(name, (kal_uintptr)n, entry + n + 1, sizeof env_text - at - (kal_uintptr)n - 1);
        if (v < 0 || at + (kal_uintptr)n + 1 + (kal_uintptr)v >= sizeof env_text) continue;
        env[env_count] = entry;
        env_lens[env_count] = (kal_uintptr)n + 1 + (kal_uintptr)v;
        ++env_count;
        at += (kal_uintptr)n + 1 + (kal_uintptr)v;
    }
}

enum { kNotStarted = -1000 };

/* Starts `path' with `argv' and answers its status; kNotStarted - the
 * openkal error where the start did not happen, and -1 where the program was
 * ended rather than exiting. */
static int run(const char* path, const char* const* argv, kal_uintptr argc) {
    struct kal_dir dir; const char* rest = 0;
    if (!locate(path, &dir, &rest)) return kNotStarted - 1000;
    struct kal_spawn how = {0};
    how.base = dir;
    how.work = dir;
    kal_uintptr lens[16];
    for (kal_uintptr i = 0; i < argc && i < 16; ++i) lens[i] = length(argv[i]);
    struct kal_spawn_streams streams = { kal_stdin(), kal_stdout(), kal_stderr() };
    struct kal_process p;
    const int rc = kal_process_spawn(&how, rest, length(rest), (const char**)argv, lens, argc,
                                     env, env_lens, env_count, &streams, &p);
    if (rc != kal_ok) return kNotStarted - rc;
    int status = 0, terminated = 0;
    if (kal_process_wait(p, &status, &terminated) != kal_ok) return kNotStarted - 999;
    return terminated ? -1 : status;
}

static char self[4096];
static char sibling[4096];

int ok_main(void) {
    char a0[64] = {0}, a1[64] = {0};
    const kal_uintptr argc = kal_env_arg_count();
    if (argc >= 1) { const kal_intptr n = kal_env_arg(0, a0, sizeof a0 - 1); if (n > 0 && n < (kal_intptr)sizeof a0) a0[n] = 0; }
    if (argc >= 2) { const kal_intptr n = kal_env_arg(1, a1, sizeof a1 - 1); if (n > 0 && n < (kal_intptr)sizeof a1) a1[n] = 0; }
    if (same(a1, "child")) return same(a0, "as-started") ? 7 : 8;

    const kal_intptr n = kal_env_image(self, sizeof self - 1);
    if (n <= 0 || n >= (kal_intptr)sizeof self - 1) { say("starts: the image has no name\n"); return 10; }
    self[n] = 0;
    take_environment();
    const char* child[] = { "as-started", "child" };
    const int itself = run(self, child, 2);

    if (same(a1, "refused")) {
        const int refused = itself == kNotStarted - kal_err_not_program;
        say("starts: itself, where no loader is named: ");
        if (refused) say("refused as not a program\n");
        else { number(itself); say(" (a refusal was expected)\n"); }
        return refused ? 0 : 11;
    }
    say("starts: itself "); number(itself); say("\n");

    kal_uintptr dir_end = 0;
    for (kal_uintptr i = 0; self[i]; ++i) if (separator(self[i])) dir_end = i + 1;
    const char name[] = "exits.oke";
    for (kal_uintptr i = 0; i < dir_end; ++i) sibling[i] = self[i];
    for (kal_uintptr i = 0; i < sizeof name; ++i) sibling[dir_end + i] = name[i];
    const char* exits_argv[] = { "exits" };
    const int exits = run(sibling, exits_argv, 1);
    say("starts: exits.oke "); number(exits); say("\n");

    int native = 5;
    if (argc >= 2) {
        static char words[8][1024];
        const char* argv[8];
        kal_uintptr count = 0;
        for (kal_uintptr i = 1; i < argc && count < 8; ++i) {
            const kal_intptr w = kal_env_arg(i, words[count], sizeof words[count] - 1);
            if (w < 0 || w >= (kal_intptr)sizeof words[count] - 1) return 12;
            words[count][w] = 0;
            argv[count] = words[count];
            ++count;
        }
        native = run(argv[0], argv, count);
        say("starts: "); say(argv[0]); say(" "); number(native); say("\n");
    }
    const int ok = itself == 7 && exits == 0 && native == 5;
    say(ok ? "starts: ok\n" : "starts: FAILED\n");
    return ok ? 0 : 1;
}
