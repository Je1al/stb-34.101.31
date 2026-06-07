// SPDX-License-Identifier: MIT
//
// belt-hash: 256-bit hash function (clause 6.9).

#include <cstring>

#include "belt_internal.hpp"

namespace belt {
namespace {

void xor16(std::uint8_t* dst, const std::uint8_t* a, const std::uint8_t* b) {
    for (std::size_t j = 0; j < kBlockSize; ++j) dst[j] = a[j] ^ b[j];
}

}  // namespace

namespace detail {

// sigma1: {0,1}^512 -> {0,1}^128 (clause 6.9.2).
// u = u1 || u2 || u3 || u4 (each 128 bits); out = F_{u1||u2}(u3^u4) ^ (u3^u4).
void sigma1(const std::uint8_t u[64], std::uint8_t out[kBlockSize]) {
    Bytes key(u, u + 2 * kBlockSize);  // u1 || u2
    const Block cipher(key);

    std::uint8_t t[kBlockSize];
    xor16(t, u + 2 * kBlockSize, u + 3 * kBlockSize);  // u3 ^ u4
    std::uint8_t enc[kBlockSize];
    cipher.encrypt(t, enc);
    xor16(out, enc, t);
}

// sigma2: {0,1}^512 -> {0,1}^256 (clause 6.9.2).
void sigma2(const std::uint8_t u[64], std::uint8_t out[2 * kBlockSize]) {
    std::uint8_t s1[kBlockSize];
    sigma1(u, s1);

    const std::uint8_t* u1 = u;
    const std::uint8_t* u2 = u + kBlockSize;
    const std::uint8_t* u3 = u + 2 * kBlockSize;
    const std::uint8_t* u4 = u + 3 * kBlockSize;

    // theta1 = sigma1(u) || u4
    Bytes theta1(2 * kBlockSize);
    std::memcpy(&theta1[0], s1, kBlockSize);
    std::memcpy(&theta1[kBlockSize], u4, kBlockSize);

    // theta2 = (sigma1(u) ^ 1^128) || u3
    Bytes theta2(2 * kBlockSize);
    for (std::size_t j = 0; j < kBlockSize; ++j) theta2[j] = s1[j] ^ 0xFF;
    std::memcpy(&theta2[kBlockSize], u3, kBlockSize);

    const Block c1(theta1);
    const Block c2(theta2);
    std::uint8_t e1[kBlockSize];
    std::uint8_t e2[kBlockSize];
    c1.encrypt(u1, e1);
    c2.encrypt(u2, e2);
    xor16(out, e1, u1);                  // (F_{theta1}(u1) ^ u1)
    xor16(out + kBlockSize, e2, u2);     // (F_{theta2}(u2) ^ u2)
}

}  // namespace detail

using detail::sigma1;
using detail::sigma2;

Bytes hash(const Bytes& data) {
    constexpr std::size_t kStep = 2 * kBlockSize;  // 256-bit message blocks

    std::uint8_t s[kBlockSize] = {0};
    std::uint8_t h[kStep];
    std::memcpy(h, detail::kSBox, kStep);  // first two rows of table H

    const std::size_t fullBlocks = data.size() / kStep;
    const std::size_t rem = data.size() % kStep;

    std::uint8_t u[64];

    const auto absorb = [&](const std::uint8_t* block) {
        std::memcpy(u, block, kStep);          // X_i
        std::memcpy(u + kStep, h, kStep);      // h
        std::uint8_t s1[kBlockSize];
        sigma1(u, s1);
        for (std::size_t j = 0; j < kBlockSize; ++j) s[j] ^= s1[j];
        sigma2(u, h);
    };

    for (std::size_t b = 0; b < fullBlocks; ++b) absorb(&data[b * kStep]);
    if (rem != 0) {
        std::uint8_t block[kStep] = {0};
        std::memcpy(block, &data[fullBlocks * kStep], rem);  // zero padding
        absorb(block);
    }

    // Y <- sigma2(<|X|>_128 || s || h)
    std::memset(u, 0, kBlockSize);
    const std::uint64_t bitLen = static_cast<std::uint64_t>(data.size()) * 8;
    for (std::size_t j = 0; j < 8; ++j) u[j] = static_cast<std::uint8_t>(bitLen >> (8 * j));
    std::memcpy(u + kBlockSize, s, kBlockSize);
    std::memcpy(u + kStep, h, kStep);

    Bytes out(kHashSize);
    sigma2(u, out.data());
    return out;
}

}  // namespace belt
