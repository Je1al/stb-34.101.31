#pragma once
#include <cstdint>
#include <vector>
#include <string>

class Belt {
public:
    Belt(const std::vector<uint8_t>& key); // Конструктор с 256-битным ключом

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const;
    void decrypt_block(const uint8_t in[16], uint8_t out[16]) const;

    std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t>& data) const;

    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& data, const uint8_t iv[16]) const;
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& data, const uint8_t iv[16]) const;

    std::vector<uint8_t> mac(const std::vector<uint8_t>& data) const;

private:
    uint32_t key_[8]; // 256-битный ключ как 8 слов
    static const uint8_t H[256]; // S-box BELT
    static uint32_t G(uint32_t x);
};
