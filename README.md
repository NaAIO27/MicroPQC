# RS-MicroPQC

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://blog.rust-lang.org/2021/10/21/Rust-1.56.0.html)

A `no_std` compatible Post-Quantum Cryptography library for embedded systems.

[中文](README.zh-CN.md) | [Deutsch](README.de.md)

## Introduction

RS-MicroPQC is a lightweight, secure post-quantum cryptography implementation optimized for resource-constrained embedded devices. Currently implements **Kyber** (NIST standardized Key Encapsulation Mechanism, ML-KEM).

### Features

- Kyber support: Implements Kyber512, Kyber768, and Kyber1024 security levels
- `no_std` compatible: No standard library required, suitable for bare-metal embedded environments
- Constant-time operations: Prevents timing attacks
- Sensitive data zeroization: Automatically clears keys and sensitive data using `zeroize`
- Pure safe Rust: `#![deny(unsafe_code)]`, 100% safe code

## Quick Start

### Dependencies

Add to your `Cargo.toml`:

```toml
[dependencies]
micropqc = "0.1.0"
```

### Example

```rust
use micropqc::{Kyber512, Kem};

// Generate keypair
let mut rng = MyRng::new();
let (pk, sk) = Kyber512::keypair(&mut rng)?;

// Encapsulate
let (ct, ss) = Kyber512::encapsulate(&mut rng, &pk)?;

// Decapsulate
let ss2 = Kyber512::decapsulate(&ct, &sk)?;
assert_eq!(ss.as_ref(), ss2.as_ref());
```

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `kyber512` | Kyber-512 security level | Yes |
| `kyber768` | Kyber-768 security level | No |
| `kyber1024` | Kyber-1024 security level | No |
| `std` | Enable standard library support | No |

### Switching Security Levels

```toml
[dependencies]
micropqc = { version = "0.1.0", default-features = false, features = ["kyber768"] }
```

## Key Sizes

| Parameter | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|------------|------------|------------|---------------|
| Kyber512 | 800 bytes | 768 bytes | 768 bytes | 32 bytes |
| Kyber768 | 1184 bytes | 1152 bytes | 1088 bytes | 32 bytes |
| Kyber1024 | 1568 bytes | 1536 bytes | 1568 bytes | 32 bytes |

## Security Levels

- **Kyber512**: NIST Security Level 1 (comparable to AES-128)
- **Kyber768**: NIST Security Level 3 (comparable to AES-192)
- **Kyber1024**: NIST Security Level 5 (comparable to AES-256)

## Platform Support

- x86_64
- ARM Cortex-M
- RISC-V
- WebAssembly (wasm32)

## Building

```bash
# Standard build
cargo build --release

# Run tests
cargo test

# Build documentation
cargo doc --no-deps
```

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Issues and Pull Requests are welcome!

## Acknowledgments

- Based on the [Kyber](https://pq-crystals.org/kyber/) reference implementation
- Thanks to NIST Post-Quantum Cryptography Standardization project

---

**Note**: This project is in early development. APIs may change. Please test thoroughly before using in production.
