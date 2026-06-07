// SPDX-License-Identifier: MIT
//
// belt — command-line front-end for the STB 34.101.31 algorithms.
//
//   belt hash [FILE]
//   belt mac  -k KEY [FILE]
//   belt enc  -m MODE -k KEY [-i IV] [IN] [OUT]
//   belt dec  -m MODE -k KEY [-i IV] [IN] [OUT]
//
// KEY and IV are hex strings. MODE is one of ecb, cbc, cfb, ctr.
// When IN/OUT are omitted, standard input/output are used. For `hash` and
// `mac` the digest is printed as hex to standard output.

#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "belt/belt.hpp"

namespace {

using belt::Bytes;

Bytes read_stream(std::istream& in) {
    return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

Bytes read_input(const std::string& path) {
    if (path.empty() || path == "-") return read_stream(std::cin);
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open input file: " + path);
    return read_stream(f);
}

void write_output(const std::string& path, const Bytes& data) {
    if (path.empty() || path == "-") {
        std::cout.write(reinterpret_cast<const char*>(data.data()),
                        static_cast<std::streamsize>(data.size()));
        return;
    }
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open output file: " + path);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

// Pulls "-k VALUE" / "-i VALUE" / "-m VALUE" options out of argv, leaving the
// positional arguments in `positional`.
struct Args {
    std::map<std::string, std::string> opts;
    std::vector<std::string> positional;
};

Args parse(int argc, char** argv, int start) {
    Args a;
    for (int i = start; i < argc; ++i) {
        std::string tok = argv[i];
        if ((tok == "-k" || tok == "-i" || tok == "-m") && i + 1 < argc) {
            a.opts[tok] = argv[++i];
        } else {
            a.positional.push_back(tok);
        }
    }
    return a;
}

std::string at(const Args& a, const std::string& key) {
    auto it = a.opts.find(key);
    return it == a.opts.end() ? std::string() : it->second;
}

int usage() {
    std::fprintf(stderr,
                 "belt — STB 34.101.31 (BelT) toolkit\n\n"
                 "Usage:\n"
                 "  belt hash [FILE]\n"
                 "  belt mac  -k KEY [FILE]\n"
                 "  belt enc  -m MODE -k KEY [-i IV] [IN] [OUT]\n"
                 "  belt dec  -m MODE -k KEY [-i IV] [IN] [OUT]\n\n"
                 "MODE = ecb | cbc | cfb | ctr   KEY,IV = hex strings\n");
    return 2;
}

Bytes run_mode(const std::string& mode, bool enc, const Bytes& key,
               const Bytes& iv, const Bytes& data) {
    if (mode == "ecb") return enc ? belt::ecb_encrypt(key, data) : belt::ecb_decrypt(key, data);
    if (mode == "cbc") return enc ? belt::cbc_encrypt(key, iv, data) : belt::cbc_decrypt(key, iv, data);
    if (mode == "cfb") return enc ? belt::cfb_encrypt(key, iv, data) : belt::cfb_decrypt(key, iv, data);
    if (mode == "ctr") return belt::ctr(key, iv, data);
    throw std::runtime_error("unknown mode: " + mode + " (use ecb|cbc|cfb|ctr)");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage();
    const std::string cmd = argv[1];

    try {
        if (cmd == "hash") {
            const Args a = parse(argc, argv, 2);
            const std::string path = a.positional.empty() ? "" : a.positional[0];
            std::cout << belt::hex::encode(belt::hash(read_input(path))) << "\n";
            return 0;
        }
        if (cmd == "mac") {
            const Args a = parse(argc, argv, 2);
            if (at(a, "-k").empty()) return usage();
            const Bytes key = belt::hex::decode(at(a, "-k"));
            const std::string path = a.positional.empty() ? "" : a.positional[0];
            std::cout << belt::hex::encode(belt::mac(key, read_input(path))) << "\n";
            return 0;
        }
        if (cmd == "enc" || cmd == "dec") {
            const Args a = parse(argc, argv, 2);
            const std::string mode = at(a, "-m");
            if (mode.empty() || at(a, "-k").empty()) return usage();
            const Bytes key = belt::hex::decode(at(a, "-k"));
            Bytes iv;
            if (!at(a, "-i").empty()) iv = belt::hex::decode(at(a, "-i"));
            const std::string in = a.positional.size() > 0 ? a.positional[0] : "";
            const std::string out = a.positional.size() > 1 ? a.positional[1] : "";
            const Bytes result = run_mode(mode, cmd == "enc", key, iv, read_input(in));
            write_output(out, result);
            return 0;
        }
        return usage();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
