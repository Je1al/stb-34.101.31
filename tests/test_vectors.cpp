// SPDX-License-Identifier: MIT
//
// Known-answer tests covering every algorithm of STB 34.101.31-2011 against the
// official test vectors from Appendix A of the standard. The program exits with
// a non-zero status if any vector fails.

#include <array>
#include <cstdio>
#include <string>

#include "belt/belt.hpp"

namespace {

int g_pass = 0;
int g_fail = 0;

using belt::Bytes;
using belt::hex::decode;
using belt::hex::encode;

void expect(const std::string& name, const Bytes& got, const std::string& want) {
    const std::string g = encode(got);
    const std::string w = encode(decode(want));  // normalise spacing/case
    if (g == w) {
        ++g_pass;
    } else {
        ++g_fail;
        std::printf("FAIL %-22s\n   expected %s\n   actual   %s\n",
                    name.c_str(), w.c_str(), g.c_str());
    }
}

void expect_true(const std::string& name, bool ok) {
    if (ok) {
        ++g_pass;
    } else {
        ++g_fail;
        std::printf("FAIL %-22s (condition was false)\n", name.c_str());
    }
}

// Keys reused across many vectors.
const char* KE = "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6";
const char* KD = "92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511";
// 384-bit sample plaintext / ciphertext used in several mode vectors.
const char* P48 =
    "B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D"
    "5BE3D61217B96181FE6786AD716B890B";
const char* C48 =
    "E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4F"
    "F33C657B637C306ADD4EA7799EB23D31";

std::array<std::uint8_t, 16> arr16(const std::string& h) {
    Bytes b = decode(h);
    std::array<std::uint8_t, 16> a{};
    for (int i = 0; i < 16; ++i) a[i] = b[i];
    return a;
}

void test_block() {
    // A.1 — block encryption.
    {
        Bytes in = decode("B194BAC80A08F53B366D008E584A5DE4");
        std::uint8_t out[16];
        belt::Block(decode(KE)).encrypt(in.data(), out);
        expect("A.1 block-encrypt", Bytes(out, out + 16),
               "69CCA1C93557C9E3D66BC3E0FA88FA6E");
    }
    // A.4 — block decryption.
    {
        Bytes in = decode("E12BDC1AE28257EC703FCCF095EE8DF1");
        std::uint8_t out[16];
        belt::Block(decode(KD)).decrypt(in.data(), out);
        expect("A.4 block-decrypt", Bytes(out, out + 16),
               "0DC5300600CAB840B38448E5E993F421");
    }
}

void test_ecb() {
    expect("A.6 ecb-enc-full", belt::ecb_encrypt(decode(KE), decode(P48)),
           "69CCA1C93557C9E3D66BC3E0FA88FA6E5F23102EF109710775017F73806DA9DC"
           "46FB2ED2CE771F26DCB5E5D1569F9AB0");
    expect("A.7 ecb-enc-partial",
           belt::ecb_encrypt(decode(KE),
                             decode("B194BAC80A08F53B366D008E584A5DE48504FA9D1B"
                                    "B6C7AC252E72C202FDCE0D5BE3D61217B96181FE67"
                                    "86AD716B89")),
           "69CCA1C93557C9E3D66BC3E0FA88FA6E36F00CFED6D1CA1498C12798F4BEB207"
           "5F23102EF109710775017F73806DA9");
    expect("A.8 ecb-dec-full", belt::ecb_decrypt(decode(KD), decode(C48)),
           "0DC5300600CAB840B38448E5E993F421E55A239F2AB5C5D5FDB6E81B40938E2A"
           "54120CA3E6E19C7AD750FC3531DAEAB7");
    expect("A.9 ecb-dec-partial",
           belt::ecb_decrypt(decode(KD),
                             decode("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389F"
                                    "E678CAF7C6F860D5BB9C4FF33C657B")),
           "0DC5300600CAB840B38448E5E993F4215780A6E2B69EAFBB258726D7B6718523"
           "E55A239F");
}

void test_cbc() {
    const char* Se = "BE32971343FC9A48A02A885F194B09A1";
    const char* Sd = "7ECDA4D01544AF8CA58450BF66D2E88A";
    expect("A.10 cbc-enc-full", belt::cbc_encrypt(decode(KE), decode(Se), decode(P48)),
           "10116EFAE6AD58EE14852E11DA1B8A745CF2480E8D03F1C19492E53ED3A70F60"
           "657C1EE8C0E0AE5B58388BF8A68E3309");
    expect("A.11 cbc-enc-partial",
           belt::cbc_encrypt(decode(KE), decode(Se),
                             decode("B194BAC80A08F53B366D008E584A5DE48504FA9D1B"
                                    "B6C7AC252E72C202FDCE0D5BE3D612")),
           "10116EFAE6AD58EE14852E11DA1B8A746A9BBADCAF73F968F875DEDC0A44F6B1"
           "5CF2480E");
    expect("A.12 cbc-dec-full", belt::cbc_decrypt(decode(KD), decode(Sd), decode(C48)),
           "730894D6158E17CC1600185A8F411CAB0471FF85C83792398D8924EBD57D03DB"
           "95B97A9B7907E4B020960455E46176F8");
    expect("A.13 cbc-dec-partial",
           belt::cbc_decrypt(decode(KD), decode(Sd),
                             decode("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389F"
                                    "E678CAF7C6F860D5BB9C4FF33C657B")),
           "730894D6158E17CC1600185A8F411CABB6AB7AF8541CF85755B8EA27239F08D2"
           "166646E4");
}

void test_cfb() {
    expect("A.14 cfb-enc",
           belt::cfb_encrypt(decode(KE), decode("BE32971343FC9A48A02A885F194B09A1"),
                             decode(P48)),
           "C31E490A90EFA374626CC99E4B7B8540A6E48685464A5A06849C9CA769A1B0AE"
           "55C2CC5939303EC832DD2FE16C8E5A1B");
    expect("A.15 cfb-dec",
           belt::cfb_decrypt(decode(KD), decode("7ECDA4D01544AF8CA58450BF66D2E88A"),
                             decode(C48)),
           "FA9D107A86F375EE65CD1DB881224BD016AFF814938ED39B3361ABB0BF0851B6"
           "52244EB06842DD4C94AA4500774E40BB");
}

void test_ctr() {
    expect("A.16 ctr",
           belt::ctr(decode(KE), decode("BE32971343FC9A48A02A885F194B09A1"),
                     decode(P48)),
           "52C9AF96FF50F64435FC43DEF56BD797D5B5B1FF79FB41257AB9CDF6E63E81F8"
           "F00341473EAE409833622DE05213773A");
}

void test_mac() {
    expect("A.17 mac-104bit",
           belt::mac(decode(KE), decode("B194BAC80A08F53B366D008E58")),
           "7260DA60138F96C9");
    expect("A.18 mac-384bit", belt::mac(decode(KE), decode(P48)),
           "2DAB59771B4B16D0");
}

void test_gf() {
    // A.19 — multiplication in GF(2^128).
    auto w1 = belt::gf_mul(arr16("3490405511BE32971343724C5AB793E9"),
                           arr16("224817838761A9D6E3EC9689110FB0F3"));
    expect("A.19 gf-mul-1", Bytes(w1.begin(), w1.end()),
           "0001D107FC67DE4004DC2C803DFD95C3");
    auto w2 = belt::gf_mul(arr16("703FCCF095EE8DF1C1ABF8EE8DF1C1AB"),
                           arr16("2055704E2EDB48FE87E74075A5E77EB1"));
    expect("A.19 gf-mul-2", Bytes(w2.begin(), w2.end()),
           "4A5C95938B3FE8F674D59BC1EB356079");
}

void test_dwp() {
    // A.20 — set protection.
    {
        auto r = belt::dwp_wrap(
            decode(KE), decode("BE32971343FC9A48A02A885F194B09A1"),
            decode("B194BAC80A08F53B366D008E584A5DE4"),
            decode("8504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD71"
                   "6B890B"));
        expect("A.20 dwp-wrap-Y", r.ciphertext, "52C9AF96FF50F64435FC43DEF56BD797");
        expect("A.20 dwp-wrap-T", r.tag, "3B2E0AEB2B91854B");
    }
    // A.21 — removal of protection (valid tag).
    {
        auto y = belt::dwp_unwrap(
            decode(KD), decode("7ECDA4D01544AF8CA58450BF66D2E88A"),
            decode("E12BDC1AE28257EC703FCCF095EE8DF1"),
            decode("C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA7799E"
                   "B23D31"),
            decode("6A2C2C94C4150DC0"));
        expect_true("A.21 dwp-unwrap-ok", y.has_value());
        if (y) expect("A.21 dwp-unwrap-Y", *y, "DF181ED008A20F43DCBBB93650DAD34B");
    }
    // Tamper detection: a flipped tag bit must be rejected.
    {
        auto y = belt::dwp_unwrap(
            decode(KD), decode("7ECDA4D01544AF8CA58450BF66D2E88A"),
            decode("E12BDC1AE28257EC703FCCF095EE8DF1"),
            decode("C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA7799E"
                   "B23D31"),
            decode("6A2C2C94C4150DC1"));
        expect_true("dwp-unwrap-tamper", !y.has_value());
    }
}

void test_kwp() {
    // A.22 — key wrap.
    expect("A.22 kwp-wrap",
           belt::kwp_wrap(decode(KE), decode("5BE3D61217B96181FE6786AD716B890B"),
                          decode("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7"
                                 "AC252E72C202FDCE0D")),
           "49A38EE108D6C742E52B774F00A6EF98B106CBD13EA4FB0680323051BC04DF76"
           "E487B055C69BCF541176169F1DC9F6C8");
    // A.23 — key unwrap.
    {
        auto y = belt::kwp_unwrap(
            decode(KD), decode("B5EF68D8E4A39E567153DE13D72254EE"),
            decode("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5"
                   "BB9C4FF33C657B637C306ADD4EA7799EB23D31"));
        expect_true("A.23 kwp-unwrap-ok", y.has_value());
        if (y)
            expect("A.23 kwp-unwrap-Y", *y,
                   "92632EE0C21AD9E09A39343E5C07DAA4889B03F2E6847EB152EC99F7A4"
                   "D9F154");
    }
    // Round-trip with a wrong header must fail.
    {
        Bytes wrapped = belt::kwp_wrap(
            decode(KE), decode("5BE3D61217B96181FE6786AD716B890B"),
            decode("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202F"
                   "DCE0D"));
        auto y = belt::kwp_unwrap(decode(KE),
                                  decode("00000000000000000000000000000000"),
                                  wrapped);
        expect_true("kwp-unwrap-badhdr", !y.has_value());
    }
    // Round-trip for a key length that is not a multiple of the block size
    // (24-byte / 192-bit key), which exercises the partial-block path.
    {
        const Bytes hdr = decode("5BE3D61217B96181FE6786AD716B890B");
        const Bytes k192 = decode("000102030405060708090A0B0C0D0E0F1011121314151617");
        Bytes wrapped = belt::kwp_wrap(decode(KE), hdr, k192);
        expect_true("kwp-rt-192-len", wrapped.size() == k192.size() + 16);
        auto y = belt::kwp_unwrap(decode(KE), hdr, wrapped);
        expect_true("kwp-rt-192", y.has_value() && *y == k192);
    }
}

void test_hash() {
    expect("A.24 hash-104bit",
           belt::hash(decode("B194BAC80A08F53B366D008E58")),
           "ABEF9725D4C5A83597A367D14494CC2542F20F659DDFECC961A3EC550CBA8C75");
    expect("A.25 hash-256bit",
           belt::hash(decode("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC25"
                             "2E72C202FDCE0D")),
           "749E4C3653AECE5E48DB4761227742EB6DBE13F4A80F7BEFF1A9CF8D10EE7786");
    expect("A.26 hash-384bit", belt::hash(decode(P48)),
           "9D02EE446FB6A29FE5C982D4B13AF9D3E90861BC4CEF27CF306BFB0B174A154A");
}

void test_keyexpand() {
    expect("A.27 keyexpand-n4",
           belt::key_expand(decode("E9DEE72C8F0C0FA62DDB49F46F739647")),
           "E9DEE72C8F0C0FA62DDB49F46F739647E9DEE72C8F0C0FA62DDB49F46F739647");
    expect("A.28 keyexpand-n6",
           belt::key_expand(decode("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED2"
                                   "47A37")),
           "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A374B09A17E8450BF66");
}

void test_keyrep() {
    const Bytes X = decode(KE);
    const Bytes D = decode("010000000000000000000000");
    const Bytes I = decode("5BE3D61217B96181FE6786AD716B890B");
    expect("A.29 keyrep-128", belt::key_rep(X, D, I, 16),
           "6BBBC2336670D31AB83DAA90D52C0541");
    expect("A.30 keyrep-192", belt::key_rep(X, D, I, 24),
           "9A2532A18CBAF145398D5A95FEEA6C825B9C197156A00275");
    expect("A.31 keyrep-256", belt::key_rep(X, D, I, 32),
           "76E166E6AB21256B6739397B672B879614B81CF05955FC3AB09343A745C48F77");
}

void test_roundtrips() {
    // Cross-checks that decryption inverts encryption for every confidentiality
    // mode on a message whose length is not a multiple of the block size.
    const Bytes key = decode(KE);
    const Bytes iv = decode("BE32971343FC9A48A02A885F194B09A1");
    const Bytes msg = decode("00112233445566778899AABBCCDDEEFF0102030405");
    expect_true("rt-ecb", belt::ecb_decrypt(key, belt::ecb_encrypt(key, msg)) == msg);
    expect_true("rt-cbc",
                belt::cbc_decrypt(key, iv, belt::cbc_encrypt(key, iv, msg)) == msg);
    expect_true("rt-cfb",
                belt::cfb_decrypt(key, iv, belt::cfb_encrypt(key, iv, msg)) == msg);
    expect_true("rt-ctr", belt::ctr(key, iv, belt::ctr(key, iv, msg)) == msg);
}

}  // namespace

int main() {
    test_block();
    test_ecb();
    test_cbc();
    test_cfb();
    test_ctr();
    test_mac();
    test_gf();
    test_dwp();
    test_kwp();
    test_hash();
    test_keyexpand();
    test_keyrep();
    test_roundtrips();

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
