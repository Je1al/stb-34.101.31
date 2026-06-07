# BelT — STB 34.101.31

A clean, modern **C++17** implementation of the Belarusian national cryptographic
standard **STB 34.101.31‑2011** (informally *BelT*), covering the *complete*
family of encryption and integrity algorithms defined by the standard.

[![CI](https://github.com/Je1al/stb-34.101.31/actions/workflows/ci.yml/badge.svg)](https://github.com/Je1al/stb-34.101.31/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)
![Standard](https://img.shields.io/badge/STB-34.101.31--2011-1f6feb.svg)

Every public primitive is verified against the **official test vectors from
Appendix A of the standard** — see [`tests/test_vectors.cpp`](tests/test_vectors.cpp).

---

## What is BelT?

STB 34.101.31 is the encryption and integrity standard of the Republic of
Belarus. It is built around a 128‑bit block cipher with a 256‑bit key and a set
of modes and constructions on top of it. This repository implements the whole
standard as a small dependency‑free library plus a command‑line tool.

| Algorithm | Clause | Description |
|-----------|:------:|-------------|
| `belt-block` | 6.1 | 128‑bit block cipher, 256‑bit key (`F`, `F⁻¹`) |
| `belt-ecb` | 6.2 | Electronic codebook mode, with ciphertext stealing |
| `belt-cbc` | 6.3 | Cipher block chaining, with ciphertext stealing |
| `belt-cfb` | 6.4 | Cipher feedback mode |
| `belt-ctr` | 6.5 | Counter mode |
| `belt-mac` | 6.6 | 64‑bit message authentication code |
| `belt-dwp` | 6.7 | Authenticated encryption with associated data (AEAD) |
| `belt-kwp` | 6.8 | Key wrapping |
| `belt-hash` | 6.9 | 256‑bit hash function |
| `belt-keyexpand` | 7.1 | Key expansion (128/192/256 → 256 bit) |
| `belt-keyrep` | 7.2 | Key transformation |

The GF(2¹²⁸) multiplication underlying `belt-dwp` is also exposed and tested.

---

## Quick start

```bash
git clone https://github.com/Je1al/stb-34.101.31.git
cd stb-34.101.31
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

This builds:

* `libbelt` — the static library,
* `belt` — the command‑line tool (`build/belt`),
* `belt-tests` — the known‑answer test suite.

No third‑party dependencies are required; only a C++17 compiler and CMake ≥ 3.16.

---

## Library usage

The whole public API lives in a single header, `belt/belt.hpp`, in namespace
`belt`. Byte buffers are plain `std::vector<std::uint8_t>` (aliased as
`belt::Bytes`).

### Hashing

```cpp
#include <belt/belt.hpp>

belt::Bytes digest = belt::hash(belt::hex::decode("b194bac80a08f53b366d008e58"));
// belt::hex::encode(digest) ==
//   "abef9725d4c5a83597a367d14494cc2542f20f659ddfecc961a3ec550cba8c75"
```

### Encryption (counter mode)

```cpp
auto key = belt::hex::decode("e9dee72c8f0c0fa6...03a98bf6");   // 16/24/32 bytes
auto iv  = belt::hex::decode("be32971343fc9a48a02a885f194b09a1");

belt::Bytes ct = belt::ctr(key, iv, plaintext);
belt::Bytes pt = belt::ctr(key, iv, ct);   // CTR encryption == decryption
```

`belt::ecb_encrypt/decrypt`, `belt::cbc_encrypt/decrypt` and
`belt::cfb_encrypt/decrypt` follow the same shape. ECB and CBC use ciphertext
stealing, so the ciphertext always has the same length as the plaintext.

### Authenticated encryption (`belt-dwp`)

```cpp
auto r = belt::dwp_wrap(key, iv, /*critical=*/secret, /*open=*/associated_data);
// r.ciphertext, r.tag (8 bytes)

std::optional<belt::Bytes> recovered =
    belt::dwp_unwrap(key, iv, r.ciphertext, associated_data, r.tag);
if (!recovered) { /* integrity check failed — data was tampered with */ }
```

### Key wrapping (`belt-kwp`)

```cpp
belt::Bytes wrapped = belt::kwp_wrap(kek, header /*16 bytes*/, key_to_wrap);
std::optional<belt::Bytes> key = belt::kwp_unwrap(kek, header, wrapped);
```

### MAC and key derivation

```cpp
belt::Bytes tag = belt::mac(key, message);                 // 8 bytes
belt::Bytes k   = belt::key_expand(short_key);             // → 32 bytes
belt::Bytes d   = belt::key_rep(key, level, header, 32);   // belt-keyrep
```

### Stateful block cipher

```cpp
belt::Block cipher(key);
std::uint8_t out[16];
cipher.encrypt(in, out);
cipher.decrypt(out, in);
```

---

## Command‑line tool

```
belt hash [FILE]
belt mac  -k KEY [FILE]
belt enc  -m MODE -k KEY [-i IV] [IN] [OUT]
belt dec  -m MODE -k KEY [-i IV] [IN] [OUT]
```

`MODE` is one of `ecb`, `cbc`, `cfb`, `ctr`; `KEY`/`IV` are hex strings.
Omitting `FILE`/`IN`/`OUT` reads from standard input and writes to standard
output, so the tool composes nicely in pipelines.

```bash
# Hash a file
belt hash document.pdf

# Encrypt and decrypt with belt-ctr
belt enc -m ctr -k e9dee72c...03a98bf6 -i be329713...194b09a1 plain.bin cipher.bin
belt dec -m ctr -k e9dee72c...03a98bf6 -i be329713...194b09a1 cipher.bin plain.bin

# Message authentication code
belt mac -k e9dee72c...03a98bf6 message.txt
```

---

## Implementation notes

* **Endianness.** Per clause 4.2.2 of the standard, all words are interpreted
  little‑endian: the first octet of a word is its least significant one. The
  `G_r` transformation is an octet substitution by the `H` table followed by a
  cyclic left rotation by `r` bits.
* **Field arithmetic.** `belt-dwp` multiplies 128‑bit words in
  GF(2¹²⁸) modulo `x¹²⁸ + x⁷ + x² + x + 1`. The reduction is the standard
  shift‑and‑reduce with the constant `0x87`.
* **Ciphertext stealing.** ECB and CBC implement the standard’s length‑preserving
  handling of a final partial block, so no padding is added.
* **Key wrapping** works for any key length that is a whole number of octets and
  at least 128 bits (including 192‑bit keys, which are not block‑aligned).

### Security considerations

This is a faithful, readable reference implementation intended for study,
interoperability testing, and non‑hostile environments. It is **not** hardened
against side‑channel attacks: the S‑box lookups and table accesses are not
constant‑time. Do not use it where timing or cache side channels are part of the
threat model without an independent review.

---

## Project layout

```
include/belt/belt.hpp     Public API (single header)
src/
  tables.cpp              The H substitution table (clause 6.1.2, Table 2)
  block.cpp               belt-block + belt-keyexpand
  modes.cpp               belt-ecb / belt-cbc / belt-cfb / belt-ctr
  mac.cpp                 belt-mac
  aead.cpp                belt-dwp + GF(2^128) multiplication
  keywrap.cpp             belt-kwp
  hash.cpp                belt-hash
  keyrep.cpp              belt-keyrep
  hex.cpp                 hex helpers
tools/belt_cli.cpp        Command-line front-end
tests/test_vectors.cpp    Appendix A known-answer tests
```

---

## References

* STB 34.101.31‑2011 — *Information technology and security. Data encryption and
  integrity algorithms.* Specification (with test vectors in Appendix A):
  <https://apmi.bsu.by/assets/files/std/belt-spec27.pdf>
* The reference implementation by the standard’s authors, *bee2*:
  <https://github.com/agievich/bee2>

---

## License

Released under the [MIT License](LICENSE).
