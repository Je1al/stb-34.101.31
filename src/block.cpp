// SPDX-License-Identifier: MIT
//
// belt-block: the 128-bit block cipher (clause 6.1) and belt-keyexpand
// (clause 7.1).

#include <stdexcept>
#include <utility>

#include "belt_internal.hpp"

namespace belt {

using detail::G;
using detail::load32;
using detail::store32;

Bytes key_expand(const Bytes& key) {
    Bytes out(kKeySize);
    switch (key.size()) {
        case 16:
            // theta5..theta8 <- theta1..theta4
            for (std::size_t i = 0; i < 16; ++i) {
                out[i] = key[i];
                out[i + 16] = key[i];
            }
            break;
        case 24:
            for (std::size_t i = 0; i < 24; ++i) out[i] = key[i];
            // theta7 <- theta1 ^ theta2 ^ theta3
            // theta8 <- theta4 ^ theta5 ^ theta6
            for (std::size_t i = 0; i < 4; ++i) {
                out[24 + i] = key[i] ^ key[4 + i] ^ key[8 + i];
                out[28 + i] = key[12 + i] ^ key[16 + i] ^ key[20 + i];
            }
            break;
        case 32:
            for (std::size_t i = 0; i < 32; ++i) out[i] = key[i];
            break;
        default:
            throw std::invalid_argument(
                "belt: key must be 16, 24 or 32 bytes long");
    }
    return out;
}

Block::Block(const Bytes& key) {
    const Bytes expanded = key_expand(key);
    for (std::size_t i = 0; i < 8; ++i) {
        key_[i] = load32(&expanded[4 * i]);
    }
}

void Block::encrypt(const std::uint8_t in[kBlockSize],
                    std::uint8_t out[kBlockSize]) const {
    // Round key K_j (1-indexed) maps to theta_{((j-1) mod 8) + 1}.
    const auto K = [this](std::uint32_t j) { return key_[(j - 1u) & 7u]; };

    std::uint32_t a = load32(in + 0);
    std::uint32_t b = load32(in + 4);
    std::uint32_t c = load32(in + 8);
    std::uint32_t d = load32(in + 12);

    for (std::uint32_t i = 1; i <= 8; ++i) {
        b ^= G(a + K(7 * i - 6), 5);
        c ^= G(d + K(7 * i - 5), 21);
        a -= G(b + K(7 * i - 4), 13);
        const std::uint32_t e = G(b + c + K(7 * i - 3), 21) ^ i;
        b += e;
        c -= e;
        d += G(c + K(7 * i - 2), 13);
        b ^= G(a + K(7 * i - 1), 21);
        c ^= G(d + K(7 * i), 5);
        std::swap(a, b);
        std::swap(c, d);
        std::swap(b, c);
    }

    // Y <- b || d || a || c
    store32(out + 0, b);
    store32(out + 4, d);
    store32(out + 8, a);
    store32(out + 12, c);
}

void Block::decrypt(const std::uint8_t in[kBlockSize],
                    std::uint8_t out[kBlockSize]) const {
    const auto K = [this](std::uint32_t j) { return key_[(j - 1u) & 7u]; };

    std::uint32_t a = load32(in + 0);
    std::uint32_t b = load32(in + 4);
    std::uint32_t c = load32(in + 8);
    std::uint32_t d = load32(in + 12);

    for (std::uint32_t i = 8; i >= 1; --i) {
        b ^= G(a + K(7 * i), 5);
        c ^= G(d + K(7 * i - 1), 21);
        a -= G(b + K(7 * i - 2), 13);
        const std::uint32_t e = G(b + c + K(7 * i - 3), 21) ^ i;
        b += e;
        c -= e;
        d += G(c + K(7 * i - 4), 13);
        b ^= G(a + K(7 * i - 5), 21);
        c ^= G(d + K(7 * i - 6), 5);
        std::swap(a, b);
        std::swap(c, d);
        std::swap(a, d);
    }

    // Y <- c || a || d || b
    store32(out + 0, c);
    store32(out + 4, a);
    store32(out + 8, d);
    store32(out + 12, b);
}

}  // namespace belt
