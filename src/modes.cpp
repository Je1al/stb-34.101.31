// SPDX-License-Identifier: MIT
//
// Confidentiality modes built on belt-block:
//   belt-ecb (clause 6.2), belt-cbc (clause 6.3),
//   belt-cfb (clause 6.4), belt-ctr (clause 6.5).
//
// belt-ecb and belt-cbc use ciphertext stealing so that the ciphertext has
// exactly the same length as the plaintext, even for messages whose length is
// not a multiple of the block size.

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "belt_internal.hpp"

namespace belt {
namespace {

void require_iv(const Bytes& iv) {
    if (iv.size() != kBlockSize) {
        throw std::invalid_argument("belt: IV (synchro value) must be 16 bytes");
    }
}

void xor_block(std::uint8_t* dst, const std::uint8_t* a, const std::uint8_t* b) {
    for (std::size_t j = 0; j < kBlockSize; ++j) dst[j] = a[j] ^ b[j];
}

// Shared ciphertext-stealing core for belt-ecb (no chaining).
Bytes ecb_process(const Block& cipher, const Bytes& data, bool encrypt) {
    if (data.size() < kBlockSize) {
        throw std::invalid_argument("belt-ecb: message must be at least 16 bytes");
    }
    const std::size_t len = data.size();
    const std::size_t full = len / kBlockSize;
    const std::size_t rem = len % kBlockSize;
    Bytes out(len);

    const auto run = [&](const std::uint8_t* in, std::uint8_t* o) {
        if (encrypt) cipher.encrypt(in, o); else cipher.decrypt(in, o);
    };

    if (rem == 0) {
        for (std::size_t off = 0; off < len; off += kBlockSize) run(&data[off], &out[off]);
        return out;
    }

    // Process every full block except the last one directly.
    std::size_t off = 0;
    for (std::size_t i = 0; i + 1 < full; ++i, off += kBlockSize) run(&data[off], &out[off]);

    // off now points at the last full block X_{n-1}, followed by the partial X_n.
    std::uint8_t t[kBlockSize];
    run(&data[off], t);  // t = E(X_{n-1}) = Y_n || r

    std::uint8_t last[kBlockSize];
    for (std::size_t j = 0; j < rem; ++j) last[j] = data[off + kBlockSize + j];  // X_n
    for (std::size_t j = rem; j < kBlockSize; ++j) last[j] = t[j];               // r
    run(last, &out[off]);                                                        // Y_{n-1}
    for (std::size_t j = 0; j < rem; ++j) out[off + kBlockSize + j] = t[j];      // Y_n
    return out;
}

}  // namespace

// ---------------------------------------------------------------- belt-ecb ---

Bytes ecb_encrypt(const Bytes& key, const Bytes& data) {
    return ecb_process(Block(key), data, /*encrypt=*/true);
}

Bytes ecb_decrypt(const Bytes& key, const Bytes& data) {
    return ecb_process(Block(key), data, /*encrypt=*/false);
}

// ---------------------------------------------------------------- belt-cbc ---

Bytes cbc_encrypt(const Bytes& key, const Bytes& iv, const Bytes& data) {
    require_iv(iv);
    if (data.size() < kBlockSize) {
        throw std::invalid_argument("belt-cbc: message must be at least 16 bytes");
    }
    const Block cipher(key);
    const std::size_t len = data.size();
    const std::size_t full = len / kBlockSize;
    const std::size_t rem = len % kBlockSize;
    Bytes out(len);

    std::uint8_t prev[kBlockSize];
    std::memcpy(prev, iv.data(), kBlockSize);

    const std::size_t directBlocks = (rem == 0) ? full : (full - 1);
    std::size_t off = 0;
    for (std::size_t i = 0; i < directBlocks; ++i, off += kBlockSize) {
        std::uint8_t tmp[kBlockSize];
        xor_block(tmp, &data[off], prev);
        cipher.encrypt(tmp, &out[off]);
        std::memcpy(prev, &out[off], kBlockSize);
    }
    if (rem == 0) return out;

    // Ciphertext stealing for the final partial block.
    std::uint8_t tmp[kBlockSize];
    xor_block(tmp, &data[off], prev);
    std::uint8_t t[kBlockSize];
    cipher.encrypt(tmp, t);  // t = Y_n || r

    std::uint8_t last[kBlockSize];
    for (std::size_t j = 0; j < rem; ++j) last[j] = data[off + kBlockSize + j] ^ t[j];  // X_n ^ Y_n
    for (std::size_t j = rem; j < kBlockSize; ++j) last[j] = t[j];                       // r
    cipher.encrypt(last, &out[off]);                                                     // Y_{n-1}
    for (std::size_t j = 0; j < rem; ++j) out[off + kBlockSize + j] = t[j];              // Y_n
    return out;
}

Bytes cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& data) {
    require_iv(iv);
    if (data.size() < kBlockSize) {
        throw std::invalid_argument("belt-cbc: message must be at least 16 bytes");
    }
    const Block cipher(key);
    const std::size_t len = data.size();
    const std::size_t full = len / kBlockSize;
    const std::size_t rem = len % kBlockSize;
    Bytes out(len);

    std::uint8_t prev[kBlockSize];
    std::memcpy(prev, iv.data(), kBlockSize);

    const std::size_t directBlocks = (rem == 0) ? full : (full - 1);
    std::size_t off = 0;
    for (std::size_t i = 0; i < directBlocks; ++i, off += kBlockSize) {
        std::uint8_t tmp[kBlockSize];
        cipher.decrypt(&data[off], tmp);
        xor_block(&out[off], tmp, prev);
        std::memcpy(prev, &data[off], kBlockSize);  // feedback = ciphertext
    }
    if (rem == 0) return out;

    // Ciphertext stealing for the final partial block.
    std::uint8_t t[kBlockSize];
    cipher.decrypt(&data[off], t);  // t = F^{-1}(X_{n-1})

    std::uint8_t last[kBlockSize];
    for (std::size_t j = 0; j < rem; ++j) last[j] = data[off + kBlockSize + j];  // X_n
    for (std::size_t j = rem; j < kBlockSize; ++j) last[j] = t[j];               // r
    std::uint8_t dec[kBlockSize];
    cipher.decrypt(last, dec);
    xor_block(&out[off], dec, prev);                                            // Y_{n-1}
    for (std::size_t j = 0; j < rem; ++j) out[off + kBlockSize + j] = t[j] ^ data[off + kBlockSize + j];  // Y_n
    return out;
}

// ---------------------------------------------------------------- belt-cfb ---

namespace {
Bytes cfb_process(const Bytes& key, const Bytes& iv, const Bytes& data, bool encrypt) {
    require_iv(iv);
    const Block cipher(key);
    const std::size_t len = data.size();
    Bytes out(len);

    std::uint8_t prev[kBlockSize];
    std::memcpy(prev, iv.data(), kBlockSize);

    std::size_t off = 0;
    while (off < len) {
        std::uint8_t gamma[kBlockSize];
        cipher.encrypt(prev, gamma);
        const std::size_t bs = std::min<std::size_t>(kBlockSize, len - off);
        for (std::size_t j = 0; j < bs; ++j) out[off + j] = data[off + j] ^ gamma[j];
        if (bs == kBlockSize) {
            // Feedback register is the ciphertext block.
            std::memcpy(prev, encrypt ? &out[off] : &data[off], kBlockSize);
        }
        off += bs;
    }
    return out;
}
}  // namespace

Bytes cfb_encrypt(const Bytes& key, const Bytes& iv, const Bytes& data) {
    return cfb_process(key, iv, data, /*encrypt=*/true);
}

Bytes cfb_decrypt(const Bytes& key, const Bytes& iv, const Bytes& data) {
    return cfb_process(key, iv, data, /*encrypt=*/false);
}

// ---------------------------------------------------------------- belt-ctr ---

Bytes ctr(const Bytes& key, const Bytes& iv, const Bytes& data) {
    require_iv(iv);
    const Block cipher(key);
    const std::size_t len = data.size();
    Bytes out(len);

    std::uint8_t s[kBlockSize];
    cipher.encrypt(iv.data(), s);  // s <- F(S)

    std::size_t off = 0;
    while (off < len) {
        // s <- s + <1>_128 (little-endian increment)
        for (std::size_t j = 0; j < kBlockSize; ++j) {
            if (++s[j] != 0) break;
        }
        std::uint8_t gamma[kBlockSize];
        cipher.encrypt(s, gamma);
        const std::size_t bs = std::min<std::size_t>(kBlockSize, len - off);
        for (std::size_t j = 0; j < bs; ++j) out[off + j] = data[off + j] ^ gamma[j];
        off += bs;
    }
    return out;
}

}  // namespace belt
