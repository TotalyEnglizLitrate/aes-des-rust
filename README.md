# AES/DES implementation in Rust – Cryptography Assignment

A minimal, educational implementation of AES‑128 and 3DES in Rust.

---

## 1. What is this?

This repository contains a single‑purpose library that implements the core
encryption/decryption functions for:

| Cipher  | Key length | Block size | Algorithm                              | Status |
| ------- | ---------- | ---------- | -------------------------------------- | ------ |
| AES‑128 | 128 bits   | 128 bits   | Substitution‑permutation network (SPN) | WIP    |
| DES     | 56 bits    | 64 bits    | Feistel network                        | WIP    |

It is **not** a production‑ready cryptographic library – it is written purely
for a college assignment, to illustrate the mechanics of the algorithms.

Written in pure Rust, no external crates are used for the core implementation of the algorithms. The following crates are used elsewhere in the code:

- aes and des crates are used for the tests to verify correctness of the custom implementation.
- clap is used for the command‑line demo utility.

---

## 3. Directory layout

```
.
├── src/
│   ├── aes.rs
│   ├── des.rs
│   ├── cryptographic_algorithm.rs # Trait for common functionality
│   ├── main.rs
├── tests/
│   ├── aes_test.rs
│   └── des_test.rs
├── Cargo.toml
└── README.md
```

---

## 4. Building

```bash
Written in Rust 1.89.0
rustup update stable

git clone https://github.com/TotalyEnglizLitrate/aes-des-rust.git
cd aes-des-rust

cargo build --release
```

Running the demo cli utility:

```bash
cargo run --release -- --help
```

---

## 5. Usage

TODO: Add examples for encrypting/decrypting files or strings using the CLI.

---

## 6. Tests

Run all tests with:

```bash
cargo test
```

---

## 7. Important Points

- **Security Disclaimer** – The implementation is deliberately simple
  and may omit timing‑attack mitigations, constant‑time comparisons, or
  secure key‑storage. **Never use this code in production.**
- **ECB mode only** - The implementation will only support ECB mode of operation.
  Other modes (CBC, CFB, etc.) are not implemented.

---

## 8. Author

_Narendra Sampath Kumar_ – `narendra24110064@snuchennai.edu.in`
