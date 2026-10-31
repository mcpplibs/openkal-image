// okb v1 (docs/okb.md): the manifest `okb.json' read, and a member of the
// archive admitted for use --- stored, an image's bytes at a multiple of
// 64 KiB, its content the one the manifest states. The JSON reader is the
// part of JSON the manifest uses (objects, arrays, strings, numbers, true,
// false, null), written out because nothing here has a C library.
#include <okld.h>
#include "bytes.h"

namespace {

using namespace okld;
using u8 = unsigned char; using u64 = unsigned long long;

constexpr int kDepth = 8;

// A key of the path being read, decoded.
struct key { char text[192]; size len = 0; };

struct reader {
    const char* p; const char* end;
    key path[kDepth]; int depth = 0;
    bool failed = false;
    char why[160] = {};

    // What is wanted, and where it goes.
    okld_okb_manifest* m = nullptr;
    const char* member = nullptr;   // okld_okb_digest's member
    u8* digest = nullptr;
    bool digest_found = false;
    int (*on_file)(const char* name, okld_size len, void* ctx) = nullptr;   // okld_okb_each_file
    void* on_file_ctx = nullptr;
    int stopped = 0;
    // okld_okb_chunks's member: its chunk size, and each chunk digest in order.
    const char* chunk_member = nullptr;
    u64* chunk_size = nullptr;
    int (*on_chunk)(u64 index, const u8 digest[32], void* ctx) = nullptr;
    void* on_chunk_ctx = nullptr;
    u64 chunk_index = 0;
    bool chunks_found = false;

    void fail(const char* s) { if (!failed) { failed = true; sentence(why, sizeof why) << s; } }
    void ws() { while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p; }
    bool at_path(int n, const char* const* names) const {
        if (depth != n) return false;
        for (int i = 0; i < n; ++i) {
            if (!names[i]) continue;   // any key
            const size l = length(names[i]);
            if (path[i].len != l) return false;
            for (size k = 0; k < l; ++k) if (path[i].text[k] != names[i][k]) return false;
        }
        return true;
    }
    bool path_is(const char* a) const { const char* n[] = { a }; return at_path(1, n); }

    int hex(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

    // A string, decoded into `out' (truncated at cap - 1, which is refused).
    bool string(char* out, size cap, size& len) {
        len = 0;
        if (p >= end || *p != '"') { fail("a string was expected"); return false; }
        ++p;
        while (p < end && *p != '"') {
            char c = *p++;
            if (static_cast<u8>(c) < 0x20) { fail("a control character inside a string"); return false; }
            if (c == '\\') {
                if (p >= end) break;
                const char e = *p++;
                switch (e) {
                    case '"': case '\\': case '/': c = e; break;
                    case 'b': c = '\b'; break; case 'f': c = '\f'; break;
                    case 'n': c = '\n'; break; case 'r': c = '\r'; break; case 't': c = '\t'; break;
                    case 'u': {
                        if (end - p < 4) { fail("a short \\u escape"); return false; }
                        int v = 0;
                        for (int i = 0; i < 4; ++i) { const int h = hex(p[i]); if (h < 0) { fail("a malformed \\u escape"); return false; } v = v * 16 + h; }
                        p += 4;
                        // A name of the manifest is ASCII; the rest of Unicode
                        // is refused rather than misread.
                        if (v >= 0x80 || v == 0) { fail("a \\u escape outside ASCII"); return false; }
                        c = static_cast<char>(v);
                        break;
                    }
                    default: fail("an unknown escape"); return false;
                }
            }
            if (len + 1 >= cap) { fail("a string longer than this reader accepts"); return false; }
            out[len++] = c;
        }
        if (p >= end) { fail("an unterminated string"); return false; }
        ++p;
        out[len] = 0;
        return true;
    }

    bool number(u64& v) {
        v = 0;
        bool any = false;
        if (p < end && *p == '-') { fail("a negative number"); return false; }
        while (p < end && *p >= '0' && *p <= '9') { v = v * 10 + static_cast<u64>(*p - '0'); ++p; any = true; }
        if (p < end && (*p == '.' || *p == 'e' || *p == 'E')) {
            // A fraction or an exponent: the manifest has none; skip it as JSON allows.
            while (p < end && ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' || *p == 'E' || *p == '+' || *p == '-')) ++p;
        }
        if (!any) fail("a number was expected");
        return any;
    }

    void put(char* dst, size cap, const char* s, size n) {
        if (n + 1 > cap) { fail("a value longer than its field"); return; }
        copy(dst, s, n); dst[n] = 0;
    }

    // A string value at the current path.
    void string_value(const char* s, size n) {
        if (m) {
            const char* arch[] = { "architectures", nullptr, "dir" };
            const char* arch_entry[] = { "architectures", nullptr, "entry" };
            if (path_is("name")) put(m->name, sizeof m->name, s, n);
            else if (path_is("version")) put(m->version, sizeof m->version, s, n);
            else if (path_is("entry")) put(m->entry, sizeof m->entry, s, n);
            else if (at_path(3, arch) || at_path(3, arch_entry)) {
                okld_okb_arch* a = arch_named(path[1].text, path[1].len);
                if (!a) return;
                if (at_path(3, arch)) put(a->dir, sizeof a->dir, s, n);
                else put(a->entry, sizeof a->entry, s, n);
            }
        }
        if (chunk_member) {
            const char* chunk_digest[] = { "files", chunk_member, "chunks", "sha256", nullptr };
            if (at_path(5, chunk_digest)) {
                u8 d[32];
                if (!hex_digest(s, n, d)) return;
                chunks_found = true;
                if (!stopped && on_chunk) stopped = on_chunk(chunk_index, d, on_chunk_ctx);
                ++chunk_index;
            }
        }
        if (member) {
            const char* file_digest[] = { "files", member, "sha256" };
            if (at_path(3, file_digest)) {
                if (n != 64) { fail("a sha256 that is not 64 hexadecimal digits"); return; }
                for (int i = 0; i < 32; ++i) {
                    const int hi = hex(s[2 * i]), lo = hex(s[2 * i + 1]);
                    if (hi < 0 || lo < 0) { fail("a sha256 that is not hexadecimal"); return; }
                    digest[i] = static_cast<u8>(hi * 16 + lo);
                }
                digest_found = true;
            }
        }
    }

    bool hex_digest(const char* s, size n, u8 out[32]) {
        if (n != 64) { fail("a sha256 that is not 64 hexadecimal digits"); return false; }
        for (int i = 0; i < 32; ++i) {
            const int hi = hex(s[2 * i]), lo = hex(s[2 * i + 1]);
            if (hi < 0 || lo < 0) { fail("a sha256 that is not hexadecimal"); return false; }
            out[i] = static_cast<u8>(hi * 16 + lo);
        }
        return true;
    }

    okld_okb_arch* arch_named(const char* s, size n) {
        for (okld_u32 i = 0; i < m->arch_count; ++i)
            if (length(m->archs[i].name) == n) {
                bool same = true;
                for (size k = 0; k < n; ++k) if (m->archs[i].name[k] != s[k]) { same = false; break; }
                if (same) return &m->archs[i];
            }
        if (m->arch_count == sizeof m->archs / sizeof m->archs[0]) { fail("more architectures than this reader accepts"); return nullptr; }
        auto* a = &m->archs[m->arch_count++];
        put(a->name, sizeof a->name, s, n);
        return a;
    }

    void value() {
        ws();
        if (failed) return;
        if (p >= end) { fail("the manifest ends early"); return; }
        if (*p == '{') {
            ++p; ws();
            if (p < end && *p == '}') { ++p; return; }
            for (;;) {
                ws();
                if (depth == kDepth) { fail("the manifest nests deeper than this reader accepts"); return; }
                key& k = path[depth];
                if (!string(k.text, sizeof k.text, k.len)) return;
                // An architecture is recorded when its object is opened, so
                // that one with no keys is still one.
                ws();
                if (p >= end || *p != ':') { fail("':' was expected"); return; }
                ++p;
                ++depth;
                {
                    const char* arch_object[] = { "architectures", nullptr };
                    if (m && at_path(2, arch_object)) arch_named(path[1].text, path[1].len);
                    const char* file_object[] = { "files", nullptr };
                    if (on_file && !stopped && at_path(2, file_object))
                        stopped = on_file(path[1].text, path[1].len, on_file_ctx);
                }
                value();
                --depth;
                if (failed) return;
                ws();
                if (p < end && *p == ',') { ++p; continue; }
                if (p < end && *p == '}') { ++p; return; }
                fail("',' or '}' was expected");
                return;
            }
        }
        if (*p == '[') {
            ++p; ws();
            if (p < end && *p == ']') { ++p; return; }
            for (;;) {
                if (depth == kDepth) { fail("the manifest nests deeper than this reader accepts"); return; }
                path[depth].len = 0; path[depth].text[0] = 0;
                ++depth; value(); --depth;
                if (failed) return;
                ws();
                if (p < end && *p == ',') { ++p; continue; }
                if (p < end && *p == ']') { ++p; return; }
                fail("',' or ']' was expected");
                return;
            }
        }
        if (*p == '"') {
            char s[256]; size n = 0;
            if (string(s, sizeof s, n)) string_value(s, n);
            return;
        }
        if ((*p >= '0' && *p <= '9') || *p == '-') {
            u64 v = 0;
            if (number(v) && m && path_is("okb")) m->okb = static_cast<okld_u32>(v);
            if (!failed && chunk_member && chunk_size) {
                const char* size_path[] = { "files", chunk_member, "chunks", "size" };
                if (at_path(4, size_path)) *chunk_size = v;
            }
            return;
        }
        auto word = [&](const char* w) {
            const size l = length(w);
            if (static_cast<size>(end - p) < l) return false;
            for (size i = 0; i < l; ++i) if (p[i] != w[i]) return false;
            p += l;
            return true;
        };
        if (word("true") || word("false") || word("null")) return;
        fail("a value was expected");
    }

    void document() {
        ws();
        if (p >= end || *p != '{') { fail("the manifest is not a JSON object"); return; }
        value();
        ws();
        if (!failed && p != end) fail("text after the manifest's object");
    }
};

bool ends_with(const char* s, size n, const char* suffix) {
    const size l = length(suffix);
    if (n < l) return false;
    for (size i = 0; i < l; ++i) if (s[n - l + i] != suffix[i]) return false;
    return true;
}

void say(okld_why* why, const char* a, const char* b = nullptr, const char* c = nullptr) {
    if (!why) return;
    sentence s(why->text, sizeof why->text);
    s << a; if (b) s << b; if (c) s << c;
}

}  // namespace

extern "C" int okld_okb_read_manifest(const void* json, okld_size n, okld_okb_manifest* out, okld_why* why) {
    fill(out, 0, sizeof *out);
    reader r{ static_cast<const char*>(json), static_cast<const char*>(json) + n };
    r.m = out;
    r.document();
    if (r.failed) { say(why, "okb.json: ", r.why); return -1; }
    if (out->okb == 0) { say(why, "okb.json: no `okb' version"); return -1; }
    if (out->okb > OKLD_OKB_VERSION) { say(why, "okb.json: written to a later version of okb than this reader reads"); return -1; }
    if (out->arch_count == 0) { say(why, "okb.json: no architecture"); return -1; }
    for (okld_u32 i = 0; i < out->arch_count; ++i) {
        auto& a = out->archs[i];
        if (!a.dir[0]) copy(a.dir, a.name, length(a.name) + 1);
        if (!a.entry[0]) {
            if (!out->entry[0]) { say(why, "okb.json: the architecture ", a.name, " names no entry, and the bundle none"); return -1; }
            copy(a.entry, out->entry, length(out->entry) + 1);
        }
    }
    return 0;
}

extern "C" int okld_okb_digest(const void* json, okld_size n, const char* member, unsigned char out[32]) {
    reader r{ static_cast<const char*>(json), static_cast<const char*>(json) + n };
    r.member = member;
    r.digest = out;
    r.document();
    if (r.failed) return -1;
    return r.digest_found ? 1 : 0;
}

extern "C" int okld_okb_each_file(const void* json, okld_size n,
                                  int (*each)(const char* name, okld_size len, void* ctx), void* ctx) {
    reader r{ static_cast<const char*>(json), static_cast<const char*>(json) + n };
    r.on_file = each;
    r.on_file_ctx = ctx;
    r.document();
    if (r.failed) return -1;
    return r.stopped;
}

extern "C" int okld_okb_is_image(const char* name, okld_size n) {
    return ends_with(name, n, ".oke") || ends_with(name, n, ".okso") ? 1 : 0;
}

namespace {
// A member's name, and what admission asks of its place: stored, within the
// archive, an image's bytes at a multiple of 64 KiB.
bool admit_layout(okld_u64 archive_size, const okld_zip_member* m, char (&name)[256], okld_why* why) {
    const size n = m->name_len < sizeof name - 1 ? m->name_len : sizeof name - 1;
    copy(name, m->name, n); name[n] = 0;
    if (m->method != 0 || m->size != m->original) { say(why, name, ": not stored; an okb member is stored as it is (docs/okb.md)"); return false; }
    if (m->data > archive_size || m->size > archive_size - m->data) { say(why, name, ": its bytes extend beyond the archive"); return false; }
    if (okld_okb_is_image(name, n) && m->data % OKLD_OKB_ALIGNMENT != 0) {
        say(why, name, ": its bytes do not begin at a multiple of 64 KiB (docs/okb.md)");
        return false;
    }
    return true;
}
}  // namespace

extern "C" int okld_okb_admit(const void* archive, okld_u64 archive_size, const okld_zip_member* m,
                              const void* json, okld_size json_n, okld_why* why) {
    char name[256];
    if (!admit_layout(archive_size, m, name, why)) return -1;
    const auto* bytes = static_cast<const u8*>(archive) + m->data;
    if (json) {
        u8 want[32], have[32];
        const int found = okld_okb_digest(json, json_n, name, want);
        if (found < 0) { say(why, "okb.json cannot be read"); return -1; }
        if (found == 0) { say(why, name, ": okb.json states no digest for it"); return -1; }
        okld_sha256(bytes, m->size, have);
        for (int i = 0; i < 32; ++i)
            if (want[i] != have[i]) { say(why, name, ": its content is not the one okb.json states (sha256)"); return -1; }
        return 0;
    }
    if (okld_crc32(0, bytes, m->size) != m->crc32) { say(why, name, ": its content does not match its CRC-32"); return -1; }
    return 0;
}

extern "C" const char* okld_okb_arch_of(okld_u32 machine) {
    return machine == 62 ? "x86_64" : machine == 183 ? "aarch64" : nullptr;
}

extern "C" int okld_okb_chunks(const void* json, okld_size n, const char* member, okld_u64* chunk_size,
                               int (*each)(okld_u64 index, const unsigned char digest[32], void* ctx), void* ctx) {
    u64 size = 0;
    reader r{ static_cast<const char*>(json), static_cast<const char*>(json) + n };
    r.chunk_member = member;
    r.chunk_size = &size;
    r.on_chunk = each;
    r.on_chunk_ctx = ctx;
    r.document();
    if (r.failed) return -1;
    if (!r.chunks_found) return 0;
    if (chunk_size) *chunk_size = size;
    return 1;
}

namespace {

// THE CHUNKS ARE SPLIT AMONG THE JOBS BY INDEX, and each job reads the
// manifest once for its own: the library holds no list of digests (it
// allocates nothing), and a manifest is a few kilobytes against megabytes
// digested. A job records the first chunk that did not hold, plus one.
constexpr u64 kJobs = 8;

struct chunk_check {
    const u8* bytes; u64 size; u64 chunk;
    const void* json; okld_size json_n; const char* name;
    u64 jobs;
    u64 bad[kJobs];
};
struct chunk_job { chunk_check* c; u64 job; };

void check_chunks(okld_u64 job, void* ctx) {
    auto& c = *static_cast<chunk_check*>(ctx);
    chunk_job j{ &c, job };
    okld_okb_chunks(c.json, c.json_n, c.name, nullptr, [](okld_u64 i, const unsigned char want[32], void* x) -> int {
        auto& j = *static_cast<chunk_job*>(x);
        auto& c = *j.c;
        if (i % c.jobs != j.job) return 0;
        const u64 at = i * c.chunk;
        if (at >= c.size) { if (!c.bad[j.job]) c.bad[j.job] = i + 1; return 1; }
        const u64 n = c.size - at < c.chunk ? c.size - at : c.chunk;
        unsigned char have[32];
        okld_sha256(c.bytes + at, n, have);
        for (int k = 0; k < 32; ++k)
            if (have[k] != want[k]) { if (!c.bad[j.job]) c.bad[j.job] = i + 1; return 1; }
        return 0;
    }, &j);
}

}  // namespace

extern "C" int okld_okb_admit_chunked(const void* archive, okld_u64 archive_size, const okld_zip_member* m,
                                      const void* json, okld_size json_n, okld_parallel parallel, void* host,
                                      okld_why* why) {
    if (!json) return okld_okb_admit(archive, archive_size, m, json, json_n, why);
    char name[256];
    if (!admit_layout(archive_size, m, name, why)) return -1;
    u64 chunk = 0, count = 0;
    const int stated = okld_okb_chunks(json, json_n, name, &chunk, [](okld_u64, const unsigned char*, void* x) -> int {
        ++*static_cast<u64*>(x);
        return 0;
    }, &count);
    if (stated < 0) { say(why, "okb.json cannot be read"); return -1; }
    if (stated == 0) return okld_okb_admit(archive, archive_size, m, json, json_n, why);
    // THE CHUNKS COVER THE MEMBER EXACTLY: as many as its size needs, none past it.
    if (chunk == 0 || count != (m->size + chunk - 1) / chunk || (m->size == 0 && count != 0)) {
        say(why, name, ": okb.json states chunks that do not cover it");
        return -1;
    }
    chunk_check c{};
    c.bytes = static_cast<const u8*>(archive) + m->data;
    c.size = m->size; c.chunk = chunk;
    c.json = json; c.json_n = json_n; c.name = name;
    c.jobs = count < kJobs ? (count ? count : 1) : kJobs;
    if (parallel) parallel(&check_chunks, c.jobs, &c, host);
    else for (u64 j = 0; j < c.jobs; ++j) check_chunks(j, &c);
    for (u64 j = 0; j < c.jobs; ++j)
        if (c.bad[j]) { say(why, name, ": its content is not the one okb.json states (sha256 of a chunk)"); return -1; }
    return 0;
}
