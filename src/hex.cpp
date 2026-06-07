// SPDX-License-Identifier: MIT
//
// Minimal hex encoding/decoding helpers.

#include <cctype>
#include <stdexcept>

#include "belt/belt.hpp"

namespace belt::hex {
namespace {

int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

Bytes decode(const std::string& text) {
    Bytes out;
    int hi = -1;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        const int v = nibble(c);
        if (v < 0) throw std::invalid_argument("hex: invalid character");
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<std::uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    if (hi >= 0) throw std::invalid_argument("hex: odd number of digits");
    return out;
}

std::string encode(const Bytes& data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

}  // namespace belt::hex
