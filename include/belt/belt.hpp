// SPDX-License-Identifier: MIT
//
// Public API for the STB 34.101.31-2011 (BelT) cryptographic standard.
//
// Every routine works on byte sequences (belt::Bytes). Keys may be 128, 192 or
// 256 bits long; they are expanded to 256 bits internally per belt-keyexpand
// (clause 7.1). The block size is always 128 bits.

#ifndef BELT_BELT_HPP
#define BELT_BELT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace belt {

/// Sequence of octets used for keys, messages, digests and ciphertexts.
using Bytes = std::vector<std::uint8_t>;

/// belt-block block size: 128 bits (clause 6.1).
inline constexpr std::size_t kBlockSize = 16;
/// Internal expanded key size: 256 bits (clause 7.1).
inline constexpr std::size_t kKeySize = 32;
/// belt-mac / belt-dwp authentication tag size: 64 bits (clauses 6.4, 6.6).
inline constexpr std::size_t kMacSize = 8;
/// belt-hash digest size: 256 bits (clause 6.9).
inline constexpr std::size_t kHashSize = 32;

// --------------------------------------------------------------- belt-block --

/// The 128-bit block cipher (clause 6.1). Keys are run through belt-keyexpand,
/// so 16-, 24- and 32-byte keys are all accepted.
class Block {
public:
    explicit Block(const Bytes& key);

    void encrypt(const std::uint8_t in[kBlockSize],
                 std::uint8_t out[kBlockSize]) const;
    void decrypt(const std::uint8_t in[kBlockSize],
                 std::uint8_t out[kBlockSize]) const;

private:
    std::uint32_t key_[8];
};

/// belt-keyexpand (clause 7.1): expand a 128/192/256-bit key to 256 bits.
Bytes key_expand(const Bytes& key);

// ----------------------------------------------------------- encryption modes

Bytes ecb_encrypt(const Bytes& key, const Bytes& data);
Bytes ecb_decrypt(const Bytes& key, const Bytes& data);

Bytes cbc_encrypt(const Bytes& key, const Bytes& iv, const Bytes& data);
Bytes cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& data);

Bytes cfb_encrypt(const Bytes& key, const Bytes& iv, const Bytes& data);
Bytes cfb_decrypt(const Bytes& key, const Bytes& iv, const Bytes& data);

/// belt-ctr (clause 6.3): counter mode. The transform is its own inverse, so
/// the same call both encrypts and decrypts.
Bytes ctr(const Bytes& key, const Bytes& iv, const Bytes& data);

// --------------------------------------------------------------- authentication

/// belt-mac (clause 6.4): 64-bit message authentication code.
Bytes mac(const Bytes& key, const Bytes& data);

/// belt-hash (clause 6.9): 256-bit hash function.
Bytes hash(const Bytes& data);

// ------------------------------------------------------ authenticated encryption

/// Output of belt-dwp authenticated encryption.
struct AeadResult {
    Bytes ciphertext;
    Bytes tag;  ///< 64-bit authentication tag.
};

/// Multiplication in GF(2^128) as used by the belt-dwp authenticator (clause 6.6).
std::array<std::uint8_t, kBlockSize> gf_mul(
    const std::array<std::uint8_t, kBlockSize>& a,
    const std::array<std::uint8_t, kBlockSize>& b);

/// belt-dwp wrap (clause 6.6): encrypt `critical` and authenticate it together
/// with the associated `open` data under a 16-byte `iv`.
AeadResult dwp_wrap(const Bytes& key, const Bytes& iv, const Bytes& critical,
                    const Bytes& open);

/// belt-dwp unwrap: verify the tag and decrypt. Returns std::nullopt when the
/// authentication check fails.
std::optional<Bytes> dwp_unwrap(const Bytes& key, const Bytes& iv,
                                const Bytes& ciphertext, const Bytes& open,
                                const Bytes& tag);

// ---------------------------------------------------------------- key wrapping

/// belt-kwp wrap (clause 6.7): wrap `keyToWrap` bound to a 16-byte `header`.
Bytes kwp_wrap(const Bytes& key, const Bytes& header, const Bytes& keyToWrap);

/// belt-kwp unwrap: returns std::nullopt when the header check fails.
std::optional<Bytes> kwp_unwrap(const Bytes& key, const Bytes& header,
                                const Bytes& wrapped);

// -------------------------------------------------------------- key derivation

/// belt-keyrep (clause 7.2): derive an `outLen`-byte key from `key` using a
/// 12-byte level `level` and a 16-byte header `header`.
Bytes key_rep(const Bytes& key, const Bytes& level, const Bytes& header,
              std::size_t outLen);

// -------------------------------------------------------------------- helpers

namespace hex {

/// Decode a hex string (embedded spaces are ignored) into bytes.
Bytes decode(const std::string& text);
/// Encode bytes as a lowercase hex string.
std::string encode(const Bytes& data);

}  // namespace hex

}  // namespace belt

#endif  // BELT_BELT_HPP
