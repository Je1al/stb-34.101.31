// SPDX-License-Identifier: MIT
//
// belt-dwp: simultaneous encryption and integrity protection of data
// (authenticated encryption with associated data, clause 6.7), together with
// the GF(2^128) multiplication it relies on (clause 4.2, operation '*').

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "belt_internal.hpp"

namespace belt {
namespace {

// 128-bit value seen as a little-endian integer; bit e is the coefficient of
// x^e in the GF(2^128) polynomial representation (clause 4.2).
struct U128 {
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;
};

U128 load128(const std::uint8_t* p) {
    U128 v;
    for (int i = 0; i < 8; ++i) {
        v.lo |= static_cast<std::uint64_t>(p[i]) << (8 * i);
        v.hi |= static_cast<std::uint64_t>(p[8 + i]) << (8 * i);
    }
    return v;
}

void store128(const U128& v, std::uint8_t* p) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>(v.lo >> (8 * i));
        p[8 + i] = static_cast<std::uint8_t>(v.hi >> (8 * i));
    }
}

// Multiplication in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1.
U128 mul(U128 a, const U128& b) {
    U128 z;
    for (int e = 0; e < 128; ++e) {
        const std::uint64_t bit =
            (e < 64) ? (b.lo >> e) : (b.hi >> (e - 64));
        if (bit & 1) {
            z.lo ^= a.lo;
            z.hi ^= a.hi;
        }
        // a <- a * x  (shift left by one, reduce when x^128 appears)
        const std::uint64_t carry = a.hi >> 63;
        a.hi = (a.hi << 1) | (a.lo >> 63);
        a.lo <<= 1;
        if (carry) a.lo ^= 0x87;
    }
    return z;
}

void store64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}

// CTR-style keystream starting from a counter base of F(S) (clause 6.7 step 2).
Bytes ctr_crypt(const Block& cipher, const std::uint8_t base[kBlockSize],
                const Bytes& data) {
    Bytes out(data.size());
    std::uint8_t s[kBlockSize];
    std::memcpy(s, base, kBlockSize);
    std::size_t off = 0;
    while (off < data.size()) {
        for (std::size_t j = 0; j < kBlockSize; ++j) {
            if (++s[j] != 0) break;
        }
        std::uint8_t gamma[kBlockSize];
        cipher.encrypt(s, gamma);
        const std::size_t bs = std::min<std::size_t>(kBlockSize, data.size() - off);
        for (std::size_t j = 0; j < bs; ++j) out[off + j] = data[off + j] ^ gamma[j];
        off += bs;
    }
    return out;
}

// Computes the 8-byte belt-dwp tag over (open, payload) using the MAC key rMac
// (= F(F(S))). `payload` is the ciphertext in both directions.
void authenticate(const Block& cipher, const U128& rMac, const Bytes& open,
                  const Bytes& payload, std::uint8_t tag[kMacSize]) {
    // s starts at the constant given by the first row of the H table.
    U128 s = load128(detail::kSBox);

    const auto absorb = [&](const Bytes& blocks) {
        std::size_t off = 0;
        while (off < blocks.size()) {
            std::uint8_t blk[kBlockSize] = {0};
            const std::size_t bs =
                std::min<std::size_t>(kBlockSize, blocks.size() - off);
            std::memcpy(blk, &blocks[off], bs);
            U128 v = load128(blk);
            s.lo ^= v.lo;
            s.hi ^= v.hi;
            s = mul(s, rMac);
            off += bs;
        }
    };

    absorb(open);
    absorb(payload);

    std::uint8_t lenblk[kBlockSize];
    store64(lenblk, static_cast<std::uint64_t>(open.size()) * 8);
    store64(lenblk + 8, static_cast<std::uint64_t>(payload.size()) * 8);
    U128 lv = load128(lenblk);
    s.lo ^= lv.lo;
    s.hi ^= lv.hi;
    s = mul(s, rMac);

    std::uint8_t sbytes[kBlockSize];
    store128(s, sbytes);
    std::uint8_t fin[kBlockSize];
    cipher.encrypt(sbytes, fin);
    std::memcpy(tag, fin, kMacSize);
}

}  // namespace

std::array<std::uint8_t, kBlockSize> gf_mul(
    const std::array<std::uint8_t, kBlockSize>& a,
    const std::array<std::uint8_t, kBlockSize>& b) {
    const U128 r = mul(load128(a.data()), load128(b.data()));
    std::array<std::uint8_t, kBlockSize> out{};
    store128(r, out.data());
    return out;
}

AeadResult dwp_wrap(const Bytes& key, const Bytes& iv, const Bytes& critical,
                    const Bytes& open) {
    if (iv.size() != kBlockSize) {
        throw std::invalid_argument("belt-dwp: IV must be 16 bytes");
    }
    const Block cipher(key);

    std::uint8_t r0[kBlockSize];
    cipher.encrypt(iv.data(), r0);  // r0 = F(S)

    AeadResult result;
    result.ciphertext = ctr_crypt(cipher, r0, critical);

    std::uint8_t rMac[kBlockSize];
    cipher.encrypt(r0, rMac);  // rMac = F(F(S))

    result.tag.resize(kMacSize);
    authenticate(cipher, load128(rMac), open, result.ciphertext, result.tag.data());
    return result;
}

std::optional<Bytes> dwp_unwrap(const Bytes& key, const Bytes& iv,
                                const Bytes& ciphertext, const Bytes& open,
                                const Bytes& tag) {
    if (iv.size() != kBlockSize) {
        throw std::invalid_argument("belt-dwp: IV must be 16 bytes");
    }
    if (tag.size() != kMacSize) return std::nullopt;
    const Block cipher(key);

    std::uint8_t r0[kBlockSize];
    cipher.encrypt(iv.data(), r0);
    std::uint8_t rMac[kBlockSize];
    cipher.encrypt(r0, rMac);

    std::uint8_t expected[kMacSize];
    authenticate(cipher, load128(rMac), open, ciphertext, expected);

    std::uint8_t diff = 0;
    for (std::size_t j = 0; j < kMacSize; ++j) diff |= expected[j] ^ tag[j];
    if (diff != 0) return std::nullopt;  // integrity check failed

    return ctr_crypt(cipher, r0, ciphertext);
}

}  // namespace belt
