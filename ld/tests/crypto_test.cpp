// SHA-512 and Ed25519 against their published vectors (FIPS 180-4, RFC 8032
// section 7.1, tests 1 to 3), so that a signature okld writes is one any
// Ed25519 implementation reads.
#include <cstdio>
#include <cstring>
#include <okld.h>

extern "C" void okld_sha512_for_test(const void*, okld_size, unsigned char[64]);
extern "C" void okld_ed25519_sign_for_test(const unsigned char[32], const void*, okld_size, unsigned char[64]);

namespace {
int failures = 0;
void bytes(const char* hex, unsigned char* out) {
    for (std::size_t i = 0; hex[2 * i]; ++i) { unsigned v; std::sscanf(hex + 2 * i, "%2x", &v); out[i] = static_cast<unsigned char>(v); }
}
void check(bool held, const char* what) { std::printf("  %s  %s\n", held ? "held" : "FAIL", what); if (!held) ++failures; }
}

int main() {
    unsigned char h[64], want[64];
    okld_sha512_for_test("abc", 3, h);
    bytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", want);
    check(std::memcmp(h, want, 64) == 0, "SHA-512 of \"abc\"");

    struct vector { const char *seed, *key, *msg, *sig; };
    const vector v[] = {
        { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
          "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
        { "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
          "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
        { "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
          "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
          "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
    };
    for (const auto& t : v) {
        unsigned char seed[32], key[32], want_key[32], msg[8] = {}, sig[64], want_sig[64];
        bytes(t.seed, seed); bytes(t.key, want_key); bytes(t.msg, msg); bytes(t.sig, want_sig);
        okld_public_key(seed, key);
        check(std::memcmp(key, want_key, 32) == 0, "an Ed25519 public key is RFC 8032's");
        okld_ed25519_sign_for_test(seed, msg, std::strlen(t.msg) / 2, sig);
        check(std::memcmp(sig, want_sig, 64) == 0, "an Ed25519 signature is RFC 8032's");
    }
    return failures;
}
