// SPDX-License-Identifier: MIT
//
// belt-keyrep: key transformation (clause 7.2). Derives a key of a chosen
// length, carrying a fresh header, from an existing key of a given level.

#include <cstring>
#include <stdexcept>

#include "belt_internal.hpp"

namespace belt {
namespace {

// The seed word r selected from clause 7.2.3 step 1, indexed by (n, m) where
// n is the source key length and m is the derived key length (both in bits).
const std::uint8_t* seed_word(std::size_t n, std::size_t m) {
    static const std::uint8_t r128_128[4] = {0xB1, 0x94, 0xBA, 0xC8};
    static const std::uint8_t r192_128[4] = {0x5B, 0xE3, 0xD6, 0x12};
    static const std::uint8_t r192_192[4] = {0x5C, 0xB0, 0xC0, 0xFF};
    static const std::uint8_t r256_128[4] = {0xE1, 0x2B, 0xDC, 0x1A};
    static const std::uint8_t r256_192[4] = {0xC1, 0xAB, 0x76, 0x38};
    static const std::uint8_t r256_256[4] = {0xF3, 0x3C, 0x65, 0x7B};

    if (n == 128 && m == 128) return r128_128;
    if (n == 192 && m == 128) return r192_128;
    if (n == 192 && m == 192) return r192_192;
    if (n == 256 && m == 128) return r256_128;
    if (n == 256 && m == 192) return r256_192;
    if (n == 256 && m == 256) return r256_256;
    return nullptr;
}

}  // namespace

Bytes key_rep(const Bytes& key, const Bytes& level, const Bytes& header,
              std::size_t outLen) {
    if (level.size() != 12) {
        throw std::invalid_argument("belt-keyrep: level D must be 12 bytes");
    }
    if (header.size() != kBlockSize) {
        throw std::invalid_argument("belt-keyrep: header I must be 16 bytes");
    }
    const std::size_t n = key.size() * 8;
    const std::size_t m = outLen * 8;
    const std::uint8_t* r = seed_word(n, m);
    if (r == nullptr) {
        throw std::invalid_argument(
            "belt-keyrep: unsupported (source, derived) key length pair");
    }

    const Bytes s = key_expand(key);  // 32-byte expanded source key

    // u = r (32 bits) || D (96 bits) || I (128 bits) || s (256 bits) = 512 bits.
    std::uint8_t u[64];
    std::memcpy(u + 0, r, 4);
    std::memcpy(u + 4, level.data(), 12);
    std::memcpy(u + 16, header.data(), kBlockSize);
    std::memcpy(u + 32, s.data(), 2 * kBlockSize);

    std::uint8_t full[kHashSize];
    detail::sigma2(u, full);  // Y' = sigma2(u)

    return Bytes(full, full + outLen);  // L_m(Y')
}

}  // namespace belt
