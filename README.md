# AES/DES implementation in Rust – Cryptography Assignment

## 1. What is this?

This repository contains a cli interface and the core encryption/decryption functions for:

| Cipher  | Key length       | Parity Bits    | Block size | Algorithm                              |
| ------- | ---------------- | -------------- | ---------- | -------------------------------------- |
| AES‑128 | 128 bits         | -              | 128 bits   | Substitution‑permutation network (SPN) |
| DES     | 64 bits          | 8 bits         | 64 bits    | Feistel network                        |
| 3DES    | 3x64 -> 192 bits | 3x8 -> 24 bits | 64 bits    | 3 key encrypt-decrypt-encrypt with DES |

It is **not** a production‑ready cryptographic tool – it is written purely
for a college assignment, to illustrate the mechanics of the algorithms.

Written in pure Rust, no external crates are used for the core implementation of the algorithms. The following crates are used elsewhere in the code:

- [rand](https://crates.io/crates/rand) is used to generate random keys.
- [clap](https://crates.io/crates/clap) is used for the command‑line utility.

## 2. Usage

It can be built using Cargo normally

The cli can be used to encrypt or decrypt files/strings using any of the supported ciphers. Input maybe provided as plaintext or hexadecimal. Output is always plaintext for decryption, and hexadecimal for encryption. UTF-8 is assumed for plaintext. _only for command line output_ UTF-8 is attempted for encrypted input, but if it fails (which is highly likely in most cases), lossy conversion is used.

```bash
❯ target/release/aes-des-rust -h
A CLI tool for AES, DES, and 3DES encryption/decryption

Usage: aes-des-rust [OPTIONS] --algorithm <ALGORITHM>

Options:
  -a, --algorithm <ALGORITHM>  Specifies the encryption algorithm to use. [possible values: aes, des, 3des]
  -m, --mode <MODE>            Specifies the operation mode. [default: encrypt] [possible values: encrypt, decrypt]
  -k, --key <KEY>              Specifies the encryption/decryption key (required for decryption).
  -s, --string <STRING>        The string to process.
  -f, --file <FILE>            The file to process.
      --hex                    Specifies that the input string is hex-encoded.
  -o, --output <OUTPUT>        Specifies the file to write the output (ciphertext or decrypted text). Ciphertext will be written in hex format.
  -h, --help                   Print help
  -V, --version                Print version
```

## 3. Security Disclaimer

- As previously mentioned, The implementation is deliberately simple and is likely to be vulnerable to attackers. **Never use this code in production.**

- **ECB mode only** - The implementation will only support ECB mode of operation.
  Other modes (CBC, CFB, etc.) are not implemented.
