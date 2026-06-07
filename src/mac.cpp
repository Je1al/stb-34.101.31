// SPDX-License-Identifier: MIT
//
// belt-mac: 64-bit message authentication code (clause 6.6).

#include "belt_internal.hpp"

namespace belt {
namespace {

// phi1(u) = u2 || u3 || u4 || (u1 ^ u2)   (clause 6.6.2)
void phi1(const std::uint8_t in[kBlockSize], std::uint8_t out[kBlockSize]) {
    for (int j = 0; j < 4; ++j) {
        out[j] = in[4 + j];
        out[4 + j] = in[8 + j];
        out[8 + j] = in[12 + j];
        out[12 + j] = in[j] ^ in[4 + j];
    }
}

// phi2(u) = (u1 ^ u4) || u1 || u2 || u3   (clause 6.6.2)
void phi2(const std::uint8_t in[kBlockSize], std::uint8_t out[kBlockSize]) {
    for (int j = 0; j < 4; ++j) {
        out[j] = in[j] ^ in[12 + j];
        out[4 + j] = in[j];
        out[8 + j] = in[4 + j];
        out[12 + j] = in[8 + j];
    }
}

}  // namespace

Bytes mac(const Bytes& key, const Bytes& data) {
    const Block cipher(key);

    std::uint8_t s[kBlockSize] = {0};
    std::uint8_t r[kBlockSize];
    cipher.encrypt(s, r);  // r <- F(0^128)

    const std::size_t len = data.size();
    std::size_t lastLen;
    if (len == 0) {
        lastLen = 0;
    } else {
        const std::size_t rem = len % kBlockSize;
        lastLen = (rem == 0) ? kBlockSize : rem;
    }
    const std::size_t lastOff = len - lastLen;

    // Absorb X_1 .. X_{n-1} (all complete blocks before the final one).
    for (std::size_t off = 0; off < lastOff; off += kBlockSize) {
        for (std::size_t j = 0; j < kBlockSize; ++j) s[j] ^= data[off + j];
        cipher.encrypt(s, s);
    }

    std::uint8_t phi[kBlockSize];
    if (lastLen == kBlockSize) {
        phi1(r, phi);
        for (std::size_t j = 0; j < kBlockSize; ++j) s[j] ^= data[lastOff + j] ^ phi[j];
    } else {
        std::uint8_t psi[kBlockSize] = {0};
        for (std::size_t j = 0; j < lastLen; ++j) psi[j] = data[lastOff + j];
        psi[lastLen] = 0x80;  // append the single '1' bit (MSB-first within the octet)
        phi2(r, phi);
        for (std::size_t j = 0; j < kBlockSize; ++j) s[j] ^= psi[j] ^ phi[j];
    }

    std::uint8_t fin[kBlockSize];
    cipher.encrypt(s, fin);
    return Bytes(fin, fin + kMacSize);
}

}  // namespace belt
