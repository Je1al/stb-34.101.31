// SPDX-License-Identifier: MIT
//
// Internal helpers shared between the belt translation units. Not part of the
// public API.

#ifndef BELT_INTERNAL_HPP
#define BELT_INTERNAL_HPP

#include <cstddef>
#include <cstdint>

#include "belt/belt.hpp"

namespace belt::detail {

/// The substitution H (Table 2 of the standard).
extern const std::uint8_t kSBox[256];

// --- Little-endian word access (clause 4.2.2: first octet is least significant)

inline std::uint32_t load32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void store32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

inline std::uint32_t rotl32(std::uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

/// Transformation G_r (clause 6.1.2): per-octet substitution by H followed by a
/// cyclic shift toward the high-order bits (left rotation) by r positions.
inline std::uint32_t G(std::uint32_t u, int r) {
    const std::uint32_t t =
        static_cast<std::uint32_t>(kSBox[u & 0xFF]) |
        (static_cast<std::uint32_t>(kSBox[(u >> 8) & 0xFF]) << 8) |
        (static_cast<std::uint32_t>(kSBox[(u >> 16) & 0xFF]) << 16) |
        (static_cast<std::uint32_t>(kSBox[(u >> 24) & 0xFF]) << 24);
    return rotl32(t, r);
}

// Compression maps shared by belt-hash (clause 6.9) and belt-keyrep
// (clause 7.2). `u` is always a 512-bit (64-byte) input word.
void sigma1(const std::uint8_t u[64], std::uint8_t out[16]);
void sigma2(const std::uint8_t u[64], std::uint8_t out[32]);

}  // namespace belt::detail

#endif  // BELT_INTERNAL_HPP
