// The okb container (docs/okb.md) as libokld writes and reads it: the digests
// against their published vectors, an archive written and read back with its
// images' bytes at multiples of 64 KiB, a ZIP64 archive, the manifest, and the
// refusals --- a member not stored, an image not aligned, a content that is not
// the stated one, a manifest signature that does not hold.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <okld.h>

namespace {
int failures = 0;
void check(bool held, const char* what) { std::printf("  %s  %s\n", held ? "held" : "FAIL", what); if (!held) ++failures; }
std::string hex(const unsigned char* p, int n) {
    std::string s; char b[3];
    for (int i = 0; i < n; ++i) { std::snprintf(b, sizeof b, "%02x", p[i]); s += b; }
    return s;
}

std::vector<unsigned char> write(const std::vector<okld_zip_input>& in) {
    const okld_u64 need = okld_zip_write(in.data(), in.size(), OKLD_OKB_ALIGNMENT, nullptr, 0);
    std::vector<unsigned char> out(need);
    const okld_u64 wrote = okld_zip_write(in.data(), in.size(), OKLD_OKB_ALIGNMENT, out.data(), out.size());
    check(wrote == need, "the writer's two passes agree on the size");
    return out;
}
}  // namespace

int main() {
    unsigned char d[32];
    okld_sha256("abc", 3, d);
    check(hex(d, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 of \"abc\" (FIPS 180-4)");
    okld_sha256("", 0, d);
    check(hex(d, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 of nothing");
    {
        const std::string m(1000, 'a');
        okld_sha256(m.data(), m.size(), d);
        check(hex(d, 32) == "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3", "SHA-256 across blocks");
    }
    {
        // A million bytes (FIPS 180-4's long message), digested whole and then
        // from an odd offset, on the processor's instructions where it has them.
        const std::string m(1000000, 'a');
        okld_sha256(m.data(), m.size(), d);
        check(hex(d, 32) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 of a million bytes");
        const std::string shifted = "x" + m;
        okld_sha256(shifted.data() + 1, m.size(), d);
        check(hex(d, 32) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 of unaligned bytes");
    }
    check(okld_crc32(0, "123456789", 9) == 0xcbf43926u, "CRC-32 of \"123456789\"");

    // An archive: a manifest, two images of two architectures, a shared image.
    const std::string image_a(100000, 'x'), image_b(70000, 'y'), lib(12345, 'z');
    unsigned char da[32], db[32], dl[32];
    okld_sha256(image_a.data(), image_a.size(), da);
    okld_sha256(image_b.data(), image_b.size(), db);
    okld_sha256(lib.data(), lib.size(), dl);
    const std::string manifest =
        "{\"okb\": 1, \"name\": \"hello\", \"version\": \"0.1.0\", \"entry\": \"hello.oke\",\n"
        " \"architectures\": {\"x86_64\": {\"dir\": \"x86_64\"}, \"aarch64\": {\"entry\": \"hello.oke\"}},\n"
        " \"files\": {\"x86_64/hello.oke\": {\"sha256\": \"" + hex(da, 32) + "\", \"size\": 100000},\n"
        "           \"aarch64/hello.oke\": {\"sha256\": \"" + hex(db, 32) + "\"},\n"
        "           \"x86_64/libtwice.okso\": {\"sha256\": \"" + hex(dl, 32) + "\"}}}";
    const auto archive = write({
        { "okb.json", manifest.data(), manifest.size(), 0 },
        { "x86_64/hello.oke", image_a.data(), image_a.size(), 1 },
        { "x86_64/libtwice.okso", lib.data(), lib.size(), 1 },
        { "aarch64/hello.oke", image_b.data(), image_b.size(), 1 },
    });
    struct tally { int members = 0; bool aligned = true, stored = true; } t;
    okld_why why{};
    okld_zip_each(archive.data(), archive.size(), [](const okld_zip_member* m, void* c) -> int {
        auto& t = *static_cast<tally*>(c);
        ++t.members;
        if (okld_okb_is_image(m->name, m->name_len) && m->data % OKLD_OKB_ALIGNMENT) t.aligned = false;
        if (m->method != 0) t.stored = false;
        return 0;
    }, &t, &why);
    check(t.members == 4, "the archive holds its four members");
    check(t.aligned, "each image's bytes begin at a multiple of 64 KiB");
    check(t.stored, "each member is stored");

    okld_zip_member m{};
    check(okld_zip_find(archive.data(), archive.size(), "x86_64/libtwice.okso", &m, &why) == 0
          && m.size == lib.size() && std::memcmp(archive.data() + m.data, lib.data(), lib.size()) == 0,
          "a member is found by name and its bytes are in place");
    check(okld_zip_find(archive.data(), archive.size(), "riscv64/hello.oke", &m, &why) == 1, "an absent member is absent");

    okld_okb_manifest man{};
    check(okld_okb_read_manifest(manifest.data(), manifest.size(), &man, &why) == 0, "the manifest is read");
    check(man.okb == 1 && std::strcmp(man.name, "hello") == 0 && std::strcmp(man.entry, "hello.oke") == 0
          && man.arch_count == 2, "the manifest's version, name, entry and architectures");
    bool arch_ok = false;
    for (okld_u32 i = 0; i < man.arch_count; ++i)
        if (std::strcmp(man.archs[i].name, "aarch64") == 0)
            arch_ok = std::strcmp(man.archs[i].dir, "aarch64") == 0 && std::strcmp(man.archs[i].entry, "hello.oke") == 0;
    check(arch_ok, "an architecture without `dir' takes its name");
    unsigned char want[32];
    check(okld_okb_digest(manifest.data(), manifest.size(), "aarch64/hello.oke", want) == 1
          && std::memcmp(want, db, 32) == 0, "a member's stated digest");

    okld_zip_find(archive.data(), archive.size(), "x86_64/hello.oke", &m, &why);
    check(okld_okb_admit(archive.data(), archive.size(), &m, manifest.data(), manifest.size(), &why) == 0,
          "an aligned, stored image with its stated content is admitted");
    check(okld_okb_admit(archive.data(), archive.size(), &m, nullptr, 0, &why) == 0,
          "without a manifest, its CRC-32 admits it");
    {
        auto changed = archive;
        changed[m.data + 10] ^= 1;
        check(okld_okb_admit(changed.data(), changed.size(), &m, manifest.data(), manifest.size(), &why) < 0
              && std::strstr(why.text, "sha256"), "a changed byte is refused against the manifest");
        check(okld_okb_admit(changed.data(), changed.size(), &m, nullptr, 0, &why) < 0
              && std::strstr(why.text, "CRC-32"), "a changed byte is refused against the CRC-32");
    }
    {
        okld_zip_member moved = m;
        moved.data += 1;
        moved.size -= 1; moved.original -= 1;
        check(okld_okb_admit(archive.data(), archive.size(), &moved, nullptr, 0, &why) < 0
              && std::strstr(why.text, "64 KiB"), "an image whose bytes are not aligned is refused");
        okld_zip_member deflated = m;
        deflated.method = 8;
        check(okld_okb_admit(archive.data(), archive.size(), &deflated, nullptr, 0, &why) < 0
              && std::strstr(why.text, "stored"), "a member that is not stored is refused");
    }

    // The manifest's signature.
    unsigned char seed[32], key[32], sig[64];
    for (int i = 0; i < 32; ++i) seed[i] = static_cast<unsigned char>(i * 7 + 1);
    okld_public_key(seed, key);
    okld_sign_message(seed, manifest.data(), manifest.size(), sig);
    check(okld_verify_message(key, manifest.data(), manifest.size(), sig) == 1, "the manifest's signature holds");
    std::string altered = manifest;
    altered[5] = '2';
    check(okld_verify_message(key, altered.data(), altered.size(), sig) < 0, "an altered manifest's signature does not hold");

    // ZIP64: more members than the 16-bit count holds.
    {
        std::vector<std::string> names(70000);
        std::vector<okld_zip_input> in;
        in.reserve(names.size());
        for (std::size_t i = 0; i < names.size(); ++i) {
            names[i] = "m/" + std::to_string(i);
            in.push_back({ names[i].c_str(), "", 0, 0 });
        }
        const auto big = write(in);
        int n = 0;
        const int r = okld_zip_each(big.data(), big.size(), [](const okld_zip_member*, void* c) -> int { ++*static_cast<int*>(c); return 0; }, &n, &why);
        check(r == 0 && n == 70000, "a ZIP64 archive's members are all read");
    }

    // Malformed archives.
    check(okld_zip_each("not a zip archive at all", 24, nullptr, nullptr, &why) < 0, "bytes that are not an archive are refused");
    {
        auto cut = archive;
        cut.resize(cut.size() - 30);
        check(okld_zip_each(cut.data(), cut.size(), nullptr, nullptr, &why) < 0, "a truncated archive is refused");
    }
    const char* later = "{\"okb\": 2, \"architectures\": {\"x86_64\": {}}, \"entry\": \"a.oke\"}";
    check(okld_okb_read_manifest(later, std::strlen(later), &man, &why) < 0
          && std::strstr(why.text, "later version"), "a later okb version is refused");
    check(okld_okb_read_manifest("{\"okb\": 1, \"entry\": ", 20, &man, &why) < 0, "a truncated manifest is refused");
    return failures;
}
