// The okb container (docs/okb.md) as libokld writes and reads it: the digests
// against their published vectors, an archive written and read back with its
// images' bytes at multiples of 64 KiB, a ZIP64 archive, the manifest, and the
// refusals --- a member not stored, an image not aligned, a content that is not
// the stated one, a manifest signature that does not hold.
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <format>
#include <string_view>
#include <string>
#include <vector>
#include <okld.h>

import mcpplibs.mtest;

using namespace mcpplibs::mtest;

namespace {
void check(bool held, const char* what) { expect(held) << what; }
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

UTest okb_test{"okb", [] {
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

    // DEFLATE (0.4): a fixed block, a dynamic one and a stored one, as zlib
    // writes them (raw, level 9 and 0), expand to their bytes; a stream cut
    // short does not; and a member stored compressed is expanded and held to
    // its digest.
    {
        auto from_hex = [](std::string_view h) {
            std::vector<unsigned char> v;
            for (std::size_t i = 0; i + 1 < h.size(); i += 2) v.push_back(static_cast<unsigned char>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
            return v;
        };
        const std::string text = "an okb member, compressed";
        // The dynamic block's bytes: 1500 words of nine, chosen by an LCG.
        static const char* const words[] = { "okrun", "image", "snapshot", "placed", "base", "kal", "region", "zzz", "q" };
        std::string many;
        unsigned x = 12345;
        for (int i = 0; i < 1500; ++i) {
            x = (x * 1103515245u + 12345u) & 0x7fffffffu;
            if (i) many += ' ';
            many += words[(x >> 16) % 9];
        }
        const auto fixed = from_hex("4bcc53c8cf4e52c84dcd4d4a2dd25148cecf2d284a2d2e4e4d0100");
        const auto stored = from_hex("011900e6ff616e206f6b62206d656d6265722c20636f6d70726573736564");
        const auto dynamic = from_hex(
        "85595952dc3010bdca5c6d92508482000dc90fa74fd9dade26532920d6c852afaf5ff7bcbfdc7f3efcba7d7d7ddd7edc"
        "3f1f6e1f0f8f4f6fafe7f35cabf6e77d6d3d7e3e5fefef9fbfdffedede9e3ffebdf6dfe746fab4bfd5ff3cfdb93fb60d"
        "b5b6d4b9b03e6a47b567b9a52d3edf5ffaf3da3ec40aa2f5bb5524bc562eabb107cc21e21e3f871cedcdbeaf3d2c814e"
        "73b87c6d5b811e649e6339a801b2748f9cbfe6ae716afb771cd2dfa02baacb7f7c3e97daab7c9c7c4867b5a5bea32dcd"
        "f7fa4636a05bb6a951ee33f20e2acae21df2cf87636bbfe9dc25eea47dbeda1418562fd6ae1f0be6ea2b64105e3b6580"
        "37dab12064495a80d0f35d0c4cd107d331f938452dde34e203bc32af2db9461d48b6f4fb40638d8815ed21880abcc0c6"
        "1c01521ac77015bfc10ad035a0f14897fec9926e62d8cc608fde95a8152360fa593c87d90ffe26cd5441f18ac860be6c"
        "db179aa2e333a21407d150bd3d15811a03147a9354e85176e59618981a3243455d4fe195d16865120b8d29e4b1cd9ea0"
        "93f137994d70581e0944c1b11285a1d0609952f8103762c2261ca443e8aa8be890b24f376fab90e8910c098715668182"
        "67e93aec2d4902f634fab8380797e0b15c652ea2005601a3bdcc6b5683f9939d033aac5fe5640bb333a589bb99a216ce"
        "8022d0e28e60a5df8fd9aa5837ff93cbac5140b3d1e025096bc0eb9b34950f8d60aab8f2f18a4a4a934d4957bb3838c0"
        "9550d4808509c1da111ac12c38d24d5cc38999268562549bd0f13a1c8a9d0006b97d956ded2b92273d4a6117981d68ca"
        "ca77cef385089ce8cbcab1545b3ab01d01ad26068161e65a80bf15d1e6e2a58372d092ae6bf2363024e85214a7e29769"
        "34291719efafde51a443e1166614b72a217020bcb75e07398a924433708071aa78040d81e265ba392d143b51bd3f7452"
        "c2fdb3c4683cd8bc72690615d3a90d4dac80076cdc650578c4b841c36ff15b1b6f1c116493a215e7b63dec8c24e0823e"
        "b56ce1141adc91f8462f38b728090d63b5f362d36f602ad356e14078bfc6be375039ba8cb6ac057857a903e564626b6d"
        "4354859b8185bc251c6868666228c429908f632c0314d9dcf6055645a3546aae0ccb220d14d2a3a42df1ed2e4af21dbb"
        "00f02923e837913172c3f230890c1b8962053e604d56a8e6c5f83a44110ac5aa5680d434adc800a3b008c6615c4c2c5b"
        "ad8a876530dece4ab6c343e9c8942066529ad21a5367d14fc85cb296cceeac738f425fcfe46c282285923495f9143563"
        "b505589aa98481626a3662d7422d0a5a6d710d27850a1bc057ac3645dd6d46a45d0a447ad04e8bcaa6b558dbbe1b4ca4"
        "d82be7f29723124a588e8cf21174c0b47d72527146f0bfcac3d05952b6a8acde7b63396962d056026f3b08f22d026ced"
        "e719c26c486fcb2d37c42a066442b54f9a20095727bb873149a2ec64634ac238d622d952a697392fcdaa40db21629a81"
        "6e3a7d9b774e0b585340f266cf645aee28022113a20bbf3a108784dcf1410c6b28d1106a541ec85fcc1e930d88e34a30"
        "c552906a86f002c3c02b548f0c7dd704a641195230de5691139566ab7f9797138fbfa2bcd0c2dc562b44cd3606127970"
        "4afd348c90625d177f5cf8c21d4f0894e2338c90a4750bd3ac34a880b784f46cb930d865df3d521f5af295c6deb5b543"
        "9e4df46674ab100f107c3abe3762a3f3c32d5bb7bc91e6a0ac21da160e3cf65cfe0f");
        auto expands = [&](const std::vector<unsigned char>& in, const std::string& want) {
            std::vector<unsigned char> out(want.size() + 16);
            int ok = 0;
            const okld_u64 n = okld_inflate(in.data(), in.size(), out.data(), out.size(), &ok);
            return ok == 1 && n == want.size() && std::equal(want.begin(), want.end(), out.begin());
        };
        check(expands(fixed, text), "a fixed DEFLATE block expands to its bytes");
        check(expands(dynamic, many), "a dynamic one does");
        check(expands(stored, text), "and a stored one");
        {
            std::vector<unsigned char> out(64);
            int ok = 1;
            okld_inflate(dynamic.data(), dynamic.size() / 2, out.data(), out.size(), &ok);
            check(ok == 0, "a stream cut short does not expand");
        }
        // An archive whose member is the dynamic stream, method 8.
        const std::string json = "{ \"okb\": 1, \"name\": \"z\", \"entry\": \"z.oke\", \"architectures\": {}, \"files\": { \"x86_64/z.oke\": { \"sha256\": \""
            + [&] { unsigned char d[32]; okld_sha256(many.data(), many.size(), d); std::string h; for (unsigned char c : d) h += std::format("{:02x}", c); return h; }()
            + "\", \"size\": " + std::to_string(many.size()) + " } } }";
        std::vector<okld_zip_input> in;
        in.push_back({ "okb.json", json.data(), json.size(), 0, 0, 0, 0 });
        in.push_back({ "x86_64/z.oke", dynamic.data(), dynamic.size(), 0, 8, many.size(), okld_crc32(0, many.data(), many.size()) });
        const auto z = write(in);
        okld_zip_member m{};
        check(okld_zip_find(z.data(), z.size(), "x86_64/z.oke", &m, &why) == 0 && m.method == 8 && m.original == many.size(),
              "a member is written compressed, its size as expanded stated");
        std::vector<unsigned char> e(m.original);
        okld_zip_member j{};
        okld_zip_find(z.data(), z.size(), "okb.json", &j, &why);
        check(okld_okb_expand(z.data(), z.size(), &m, z.data() + j.data, j.size, e.data(), e.size(), &why) == 0
              && std::equal(many.begin(), many.end(), e.begin()), "and expanded, held to the digest okb.json states");
        check(okld_okb_admit(z.data(), z.size(), &m, z.data() + j.data, j.size, &why) != 0, "it is not admitted as it is stored");
        std::vector<unsigned char> damaged = z;
        damaged[m.data + m.size / 2] ^= 0x55;
        check(okld_okb_expand(damaged.data(), damaged.size(), &m, damaged.data() + j.data, j.size, e.data(), e.size(), &why) != 0,
              "a changed byte of it is refused");
    }

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
    const char* later = "{\"okb\": 3, \"architectures\": {\"x86_64\": {}}, \"entry\": \"a.oke\"}";
    check(okld_okb_read_manifest(later, std::strlen(later), &man, &why) < 0
          && std::strstr(why.text, "later version"), "a later okb version is refused");
    check(okld_okb_read_manifest("{\"okb\": 1, \"entry\": ", 20, &man, &why) < 0, "a truncated manifest is refused");

    // CHUNK DIGESTS (0.1.8): an image's chunks are verified instead of its
    // whole digest, one after another or as the caller runs them.
    {
        std::string big(2 * OKLD_OKB_CHUNK + OKLD_OKB_CHUNK / 2, '\0');
        for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>((i * 131) % 251);
        unsigned char whole[32];
        okld_sha256(big.data(), big.size(), whole);
        std::string list;
        for (std::size_t at = 0; at < big.size(); at += OKLD_OKB_CHUNK) {
            unsigned char c[32];
            okld_sha256(big.data() + at, std::min<std::size_t>(OKLD_OKB_CHUNK, big.size() - at), c);
            list += std::string(at ? ", " : "") + "\"" + hex(c, 32) + "\"";
        }
        const auto chunked = [&](const std::string& chunks) {
            return "{\"okb\": 1, \"entry\": \"big.oke\", \"architectures\": {\"x86_64\": {}},\n"
                   " \"files\": {\"x86_64/big.oke\": {\"sha256\": \"" + hex(whole, 32) + "\", \"size\": "
                   + std::to_string(big.size()) + chunks + "}}}";
        };
        const std::string with = chunked(", \"chunks\": {\"size\": " + std::to_string(OKLD_OKB_CHUNK) + ", \"sha256\": [" + list + "]}");
        okld_u64 chunk = 0;
        int counted = 0;
        check(okld_okb_chunks(with.data(), with.size(), "x86_64/big.oke", &chunk, [](okld_u64, const unsigned char*, void* c) -> int {
                  ++*static_cast<int*>(c);
                  return 0;
              }, &counted) == 1 && chunk == OKLD_OKB_CHUNK && counted == 3, "the manifest states three chunks of 1 MiB");
        const auto pack = [&](const std::string& json, const std::string& image) {
            return write({ { "okb.json", json.data(), json.size(), 0 }, { "x86_64/big.oke", image.data(), image.size(), 1 } });
        };
        const auto admit = [&](const std::vector<unsigned char>& a, const std::string& json, okld_parallel run, okld_why* w) {
            okld_zip_member m{};
            if (okld_zip_find(a.data(), a.size(), "x86_64/big.oke", &m, w) != 0) return -2;
            return okld_okb_admit_chunked(a.data(), a.size(), &m, json.data(), json.size(), run, nullptr, w);
        };
        const auto good = pack(with, big);
        check(admit(good, with, nullptr, &why) == 0, "its chunks hold, one after another");
        int jobs_run = 0;
        static int* seen = nullptr;
        seen = &jobs_run;
        check(admit(good, with, [](void (*job)(okld_u64, void*), okld_u64 n, void* c, void*) {
                  for (okld_u64 i = n; i-- > 0;) { job(i, c); ++*seen; }
              }, &why) == 0 && jobs_run == 3, "and as the caller runs them, in any order");
        std::string changed = big;
        changed[2 * OKLD_OKB_CHUNK + 7] ^= 1;
        check(admit(pack(with, changed), with, nullptr, &why) < 0 && std::strstr(why.text, "chunk"),
              "a changed byte in the last chunk is refused, naming a chunk");
        const std::string short_list = chunked(", \"chunks\": {\"size\": " + std::to_string(OKLD_OKB_CHUNK) + ", \"sha256\": ["
                                               + list.substr(0, list.rfind(',')) + "]}");
        check(admit(pack(short_list, big), short_list, nullptr, &why) < 0 && std::strstr(why.text, "cover"),
              "chunks that do not cover the member are refused");
        const std::string without = chunked("");
        check(admit(pack(without, big), without, nullptr, &why) == 0, "without chunks, the whole digest is verified");
        check(admit(pack(without, changed), without, nullptr, &why) < 0, "and refuses a changed byte");
    }
}};
