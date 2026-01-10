# Implementation of the Belarusian Cryptographic Standard  
## STB 34.101.31 ("BELT")

This repository contains a C++ implementation of the BELT block cipher, as defined in the national Belarusian cryptographic standard **STB 34.101.31**.

The project is fully functional, but it is designed primarily as an **educational implementation**. The main focus is on understanding the internal mechanics of the algorithm, especially the **G-transformation** and the structure of the standard-defined **S-boxes**, rather than on performance optimization or side-channel resistance.

---

## Key Features

- **Core Cipher**
  - 128-bit block cipher with a 256-bit key

- **Standard S-box**
  - Full implementation of the `H` substitution table as specified in STB 34.101.31

- **Operational Modes**
  - **ECB (Electronic Codebook)**  
    Basic block-by-block encryption with PKCS#7 padding
  - **CBC (Cipher Block Chaining)**  
    Standard chaining mode using a 128-bit Initialization Vector (IV)
  - **MAC (Message Authentication Code)**  
    64-bit integrity check (имитовставка) based on the cipher’s internal state

- **File I/O**
  - Command-line interface for encrypting and decrypting both console input and binary files

---

## Technical Details

The implementation follows a clear and direct approach, prioritizing transparency of the algorithm steps.

- **Key Schedule**
  - The 256-bit key is split into eight 32-bit words

- **G-Transformation**
  - Uses the standard-defined S-box for byte substitution
  - Followed by fixed bitwise rotations

- **Padding**
  - PKCS#7 padding is used to align data to the 128-bit block size

---

## Project Structure

- `belt.hpp` / `belt.cpp`  
  Cryptographic primitives and block cipher mode implementations

- `main.cpp`  
  Command-line driver for hex-encoded key and IV input, as well as file processing

---

## Usage

### Compile
```bash
g++ main.cpp belt.cpp -o belt_tool
