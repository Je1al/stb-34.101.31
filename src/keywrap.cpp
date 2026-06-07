// SPDX-License-Identifier: MIT
//
// belt-kwp: key wrapping (clause 6.8).
//
// The construction is a "wide block" balanced network run for 2n rounds over
// the word r = X || I (the wrapped key followed by its 16-byte header). Each
// round folds the leading blocks through belt-block and rotates r by one block,
// so the scheme works for any key length that is a whole number of octets, not
// just multiples of the block size.

#include <cstring>
#include <stdexcept>

#include "belt_internal.hpp"

namespace belt {
namespace {

void xor16(std::uint8_t* dst, const std::uint8_t* src) {
    for (std::size_t j = 0; j < kBlockSize; ++j) dst[j] ^= src[j];
}

// block ^= <round>_128 (only the low octets of the little-endian counter matter)
void add_round(std::uint8_t block[kBlockSize], std::size_t round) {
    for (std::size_t j = 0; j < sizeof(std::size_t); ++j)
        block[j] ^= static_cast<std::uint8_t>(round >> (8 * j));
}

}  // namespace

Bytes kwp_wrap(const Bytes& key, const Bytes& header, const Bytes& keyToWrap) {
    if (header.size() != kBlockSize) {
        throw std::invalid_argument("belt-kwp: header must be 16 bytes");
    }
    if (keyToWrap.size() < kBlockSize) {
        throw std::invalid_argument("belt-kwp: wrapped key must be at least 16 bytes");
    }
    const Block cipher(key);

    Bytes r;
    r.reserve(keyToWrap.size() + kBlockSize);
    r.insert(r.end(), keyToWrap.begin(), keyToWrap.end());
    r.insert(r.end(), header.begin(), header.end());  // r <- X || I

    const std::size_t N = r.size();
    const std::size_t n = (N + kBlockSize - 1) / kBlockSize;  // number of blocks

    std::uint8_t block[kBlockSize];
    for (std::size_t round = 1; round <= 2 * n; ++round) {
        // block <- r1 + r2 + ... + r_{n-1}
        std::memcpy(block, &r[0], kBlockSize);
        for (std::size_t i = kBlockSize; i + kBlockSize < N; i += kBlockSize)
            xor16(block, &r[i]);
        // r <- ShLo^128(r), then r* <- block
        std::memmove(&r[0], &r[kBlockSize], N - kBlockSize);
        std::memcpy(&r[N - kBlockSize], block, kBlockSize);
        // block <- F(block) ^ <round>
        cipher.encrypt(block, block);
        add_round(block, round);
        // the block that became r_{n-1} after the shift absorbs the keystream
        xor16(&r[N - 2 * kBlockSize], block);
    }
    return r;
}

std::optional<Bytes> kwp_unwrap(const Bytes& key, const Bytes& header,
                                const Bytes& wrapped) {
    if (header.size() != kBlockSize) {
        throw std::invalid_argument("belt-kwp: header must be 16 bytes");
    }
    if (wrapped.size() < 2 * kBlockSize) return std::nullopt;  // |X| must be >= 256 bits
    const Block cipher(key);

    Bytes r = wrapped;
    const std::size_t N = r.size();
    const std::size_t n = (N + kBlockSize - 1) / kBlockSize;

    std::uint8_t block[kBlockSize];
    for (std::size_t round = 2 * n; round >= 1; --round) {
        // block <- r*
        std::memcpy(block, &r[N - kBlockSize], kBlockSize);
        // r <- ShHi^128(r), then r1 <- block
        std::memmove(&r[kBlockSize], &r[0], N - kBlockSize);
        std::memcpy(&r[0], block, kBlockSize);
        // block <- F(block) ^ <round>
        cipher.encrypt(block, block);
        add_round(block, round);
        // r* <- r* ^ block
        xor16(&r[N - kBlockSize], block);
        // r1 <- r1 + r2 + ... + r_{n-1}
        for (std::size_t i = kBlockSize; i + kBlockSize < N; i += kBlockSize)
            xor16(&r[0], &r[i]);
    }

    // r* must equal the expected header I.
    for (std::size_t j = 0; j < kBlockSize; ++j)
        if (r[N - kBlockSize + j] != header[j]) return std::nullopt;

    r.resize(N - kBlockSize);  // Y <- r**
    return r;
}

}  // namespace belt
