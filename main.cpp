#include "belt.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>

std::vector<uint8_t> hex2bytes(const std::string& s) {
    std::vector<uint8_t> v;
    if (s.size() % 2 != 0) throw std::runtime_error("Hex string length must be even");
    for (size_t i = 0; i < s.size(); i += 2)
        v.push_back(std::stoi(s.substr(i,2), nullptr, 16));
    return v;
}

std::string bytes2hex(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (auto b: v) oss << std::hex << std::setw(2) << std::setfill('0') << int(b);
    return oss.str();
}

// Чтение файла в вектор байт
std::vector<uint8_t> read_file(const std::string& filename) {
    std::ifstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file: " + filename);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    return data;
}

// Запись вектора байт в файл
void write_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write to file: " + filename);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    std::cout << "Input mode: 1-console, 2-file: ";
    int mode; std::cin >> mode;
    std::cin.ignore();

    std::vector<uint8_t> data;
    if (mode == 1) {
        std::cout << "Enter text: ";
        std::string text; std::getline(std::cin, text);
        data = std::vector<uint8_t>(text.begin(), text.end());
    } else if (mode == 2) {
        std::cout << "Enter input filename: ";
        std::string filename; std::getline(std::cin, filename);
        data = read_file(filename);
    } else {
        std::cerr << "Invalid mode\n"; return 1;
    }

    std::cout << "Enter 256-bit key (64 hex): ";
    std::string khex; std::getline(std::cin, khex);
    if (khex.size() != 64) { std::cerr << "Invalid key length\n"; return 1; }
    auto key = hex2bytes(khex);

    std::cout << "Enter 128-bit IV (32 hex): ";
    std::string ivhex; std::getline(std::cin, ivhex);
    if (ivhex.size() != 32) { std::cerr << "Invalid IV length\n"; return 1; }
    auto iv = hex2bytes(ivhex);

    Belt belt(key);

    auto ecb = belt.encrypt_ecb(data);
    std::cout << "ECB encrypted: " << bytes2hex(ecb) << "\n";
    auto dec_ecb = belt.decrypt_ecb(ecb);
    std::cout << "ECB decrypted: " << std::string(dec_ecb.begin(), dec_ecb.end()) << "\n\n";

    auto cbc = belt.encrypt_cbc(data, iv.data());
    std::cout << "CBC encrypted: " << bytes2hex(cbc) << "\n";
    auto dec_cbc = belt.decrypt_cbc(cbc, iv.data());
    std::cout << "CBC decrypted: " << std::string(dec_cbc.begin(), dec_cbc.end()) << "\n\n";

    auto mac1 = belt.mac(data);
    std::cout << "MAC original: " << bytes2hex(mac1) << "\n";

    // 1-битная модификация для проверки MAC
    data[0] ^= 1;
    auto mac2 = belt.mac(data);
    std::cout << "MAC modified: " << bytes2hex(mac2) << "\n\n";
    if (mac1 != mac2) std::cout << "MAC changed after 1-bit modification\n";

    // Запись зашифрованных данных в файл
    if (mode == 2) {
        std::cout << "Enter output filename to save encrypted CBC data: ";
        std::string outname; std::getline(std::cin, outname);
        write_file(outname, cbc);
        std::cout << "Encrypted CBC data saved to " << outname << "\n";
    }

    return 0;
}
