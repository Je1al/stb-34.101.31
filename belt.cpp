#include "belt.hpp"
#include <cstring>
#include <stdexcept>
#include <algorithm>

static uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Таблица подстановки H (256 байт) из стандарта СТБ 34.101.31
const uint8_t Belt::H[256] = {
    0xB1,0x94,0xBA,0xC7,0xF3,0x0A,0xA4,0x2C,0x3D,0x13,0x0C,0x02,0xB5,0x6B,0x37,0x7F,
    0x2B,0x7C,0x2E,0x33,0x1D,0x3A,0xFF,0x19,0x04,0x1C,0xD3,0xED,0x43,0x48,0x99,0x61,
    0x7A,0xD7,0xC6,0x22,0x6C,0xA7,0xE3,0x8A,0x3E,0x56,0xD5,0xAE,0x55,0xA1,0x08,0xC3,
    0x87,0x6D,0xD9,0xE2,0xF0,0x9C,0xE9,0x75,0x38,0xF5,0x29,0x7E,0x96,0x4A,0xD2,0x8E,
    0x14,0xAF,0x89,0xFC,0xA8,0x01,0x9D,0xE5,0x8B,0xF9,0x36,0x42,0x0F,0x97,0x16,0x4E,
    0xD6,0xCC,0xF8,0x6A,0x1E,0xF1,0xB7,0x62,0x05,0xB0,0xBB,0xC5,0xEA,0xE0,0x35,0x26,
    0x17,0x21,0x12,0x6F,0x98,0x83,0x7B,0xC2,0x64,0x3F,0xD0,0xD1,0xC4,0x31,0xA5,0x9F,
    0x4F,0x11,0x2A,0x84,0x0B,0x59,0xAC,0xB9,0x09,0xC0,0x5A,0xEC,0xBF,0xF6,0xAA,0x28,
    0xB6,0x3B,0xA9,0x63,0x0D,0xF4,0x8D,0x39,0x6E,0x1B,0xE1,0x5E,0xF2,0xA2,0x4B,0x0E,
    0xD4,0xE4,0xCA,0x4C,0x1F,0xBF,0xA0,0xFD,0x46,0x5D,0x57,0x07,0x20,0x2D,0x70,0x5F,
    0x44,0x41,0x91,0x3C,0x71,0xC8,0xB4,0xEC,0x86,0xEF,0x66,0x9E,0x6B,0x32,0x8C,0xB8,
    0x8F,0x92,0x1A,0xAA,0x0A,0x51,0x0C,0x50,0x1C,0x5B,0xAD,0x82,0xC1,0xF7,0xC9,0xF8,
    0xC0,0xF9,0x03,0x30,0xFD,0x2F,0xA3,0xAC,0x34,0x0F,0x5C,0xE6,0xE8,0xB3,0xCE,0x47,
    0xDB,0x8B,0x9B,0xA6,0x24,0x49,0xBE,0x7D,0xF1,0x2C,0x1B,0xEA,0x88,0xB2,0xF5,0x09,
    0x52,0xD8,0xC7,0xED,0x15,0x2B,0xCA,0x68,0x90,0x7E,0x36,0xAB,0x6D,0xCE,0x45,0x3A,
    0x5D,0xB5,0x67,0xBF,0xD6,0x23,0xF0,0x81,0x19,0x33,0x02,0x10,0xA7,0x7F,0x54,0x40
};

Belt::Belt(const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::runtime_error("Key must be 256 bits (32 bytes)");
    for (int i = 0; i < 8; ++i) {
        key_[i] = (uint32_t(key[4*i]) << 24) | (uint32_t(key[4*i+1]) << 16) |
                  (uint32_t(key[4*i+2]) << 8) | uint32_t(key[4*i+3]);
    }
}

// Функция G по стандарту (разбиваем на 4 байта, подставляем через H)
uint32_t Belt::G(uint32_t x) {
    uint32_t y = 0;
    for (int i = 0; i < 4; ++i) {
        uint8_t b = (x >> (24 - 8*i)) & 0xFF;
        uint8_t s = H[b];
        y |= uint32_t(s) << (24 - 8*i);
    }
    return y;
}

// Один такт (belt-block), 8 шагов
void Belt::encrypt_block(const uint8_t in[16], uint8_t out[16]) const {
    uint32_t a[4];
    for (int i = 0; i < 4; ++i) {
        a[i] = (uint32_t(in[4*i]) << 24) | (uint32_t(in[4*i+1]) << 16) |
               (uint32_t(in[4*i+2]) << 8) | uint32_t(in[4*i+3]);
    }

    for (int i = 0; i < 8; ++i) {
        uint32_t e = a[0] + key_[i % 8];
        a[1] ^= G(e);
        e = a[1] + key_[(i+1)%8];
        a[2] ^= G(e);
        e = a[2] + key_[(i+2)%8];
        a[3] ^= G(e);
        e = a[3] + key_[(i+3)%8];
        a[0] ^= G(e);
    }

    for (int i = 0; i < 4; ++i) {
        out[4*i] = a[i] >> 24;
        out[4*i+1] = a[i] >> 16;
        out[4*i+2] = a[i] >> 8;
        out[4*i+3] = a[i];
    }
}

// Дешифрование — зеркально
void Belt::decrypt_block(const uint8_t in[16], uint8_t out[16]) const {
    uint32_t a[4];
    for (int i = 0; i < 4; ++i) {
        a[i] = (uint32_t(in[4*i]) << 24) | (uint32_t(in[4*i+1]) << 16) |
               (uint32_t(in[4*i+2]) << 8) | uint32_t(in[4*i+3]);
    }

    for (int i = 7; i >= 0; --i) {
        uint32_t e = a[3] + key_[(i+3)%8];
        a[0] ^= G(e);
        e = a[2] + key_[(i+2)%8];
        a[3] ^= G(e);
        e = a[1] + key_[(i+1)%8];
        a[2] ^= G(e);
        e = a[0] + key_[i%8];
        a[1] ^= G(e);
    }

    for (int i = 0; i < 4; ++i) {
        out[4*i] = a[i] >> 24;
        out[4*i+1] = a[i] >> 16;
        out[4*i+2] = a[i] >> 8;
        out[4*i+3] = a[i];
    }
}

// PKCS#7 padding
static std::vector<uint8_t> pad(const std::vector<uint8_t>& data) {
    size_t n = data.size();
    size_t pad_len = 16 - (n % 16);
    std::vector<uint8_t> res = data;
    res.insert(res.end(), pad_len, static_cast<uint8_t>(pad_len));
    return res;
}

static std::vector<uint8_t> unpad(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > 16) throw std::runtime_error("Invalid padding");
    return std::vector<uint8_t>(data.begin(), data.end()-pad_len);
}

// ECB режим
std::vector<uint8_t> Belt::encrypt_ecb(const std::vector<uint8_t>& data) const {
    auto in = pad(data);
    std::vector<uint8_t> out(in.size());
    for (size_t i = 0; i < in.size(); i += 16)
        encrypt_block(&in[i], &out[i]);
    return out;
}

std::vector<uint8_t> Belt::decrypt_ecb(const std::vector<uint8_t>& data) const {
    if (data.size() % 16 != 0) throw std::runtime_error("Invalid data length for ECB");
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); i += 16)
        decrypt_block(&data[i], &out[i]);
    return unpad(out);
}

// CBC режим
std::vector<uint8_t> Belt::encrypt_cbc(const std::vector<uint8_t>& data, const uint8_t iv[16]) const {
    auto in = pad(data);
    std::vector<uint8_t> out(in.size());
    uint8_t block[16];
    std::memcpy(block, iv, 16);
    for (size_t i = 0; i < in.size(); i += 16) {
        for (int j = 0; j < 16; ++j) block[j] ^= in[i+j];
        encrypt_block(block, &out[i]);
        std::memcpy(block, &out[i], 16);
    }
    return out;
}

std::vector<uint8_t> Belt::decrypt_cbc(const std::vector<uint8_t>& data, const uint8_t iv[16]) const {
    if (data.size() % 16 != 0) throw std::runtime_error("Invalid data length for CBC");
    std::vector<uint8_t> out(data.size());
    uint8_t prev[16];
    std::memcpy(prev, iv, 16);
    uint8_t tmp[16];
    for (size_t i = 0; i < data.size(); i += 16) {
        decrypt_block(&data[i], tmp);
        for (int j = 0; j < 16; ++j) out[i+j] = tmp[j] ^ prev[j];
        std::memcpy(prev, &data[i], 16);
    }
    return unpad(out);
}

// MAC (64-битная имитовставка)
std::vector<uint8_t> Belt::mac(const std::vector<uint8_t>& data) const {
    uint8_t block[16] = {0};
    size_t n = data.size();
    for (size_t i = 0; i < n; ++i) {
        block[i%16] ^= data[i];
        if ((i%16)==15 || i==n-1) encrypt_block(block, block);
    }
    return std::vector<uint8_t>(block, block+8);
}
