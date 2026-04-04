# RS-MicroPQC

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://blog.rust-lang.org/2021/10/21/Rust-1.56.0.html)

Eine `no_std`-kompatible Post-Quantum-Kryptographie-Bibliothek fur eingebettete Systeme.

[English](README.md) | [中文](README.zh-CN.md)

## Einfuhrung

RS-MicroPQC ist eine leichtgewichtige, sichere Implementierung von Post-Quantum-Kryptographie, optimiert fur ressourcenbeschrankte eingebettete Gerate. Derzeit wird **Kyber** implementiert (NIST-standardisierter Key Encapsulation Mechanism, ML-KEM).

### Funktionen

- Kyber-Unterstützung: Implementiert Kyber512, Kyber768 und Kyber1024 Sicherheitsstufen
- `no_std`-kompatibel: Keine Standardbibliothek erforderlich, geeignet für Bare-Metal-Umgebungen
- Konstantzeit-Operationen: Verhindert Timing-Angriffe
- Zeroisierung sensibler Daten: Automatisches Löschen von Schlusseln und sensiblen Daten mit `zeroize`
- Reines sicheres Rust: `#![deny(unsafe_code)]`, 100% sicherer Code

## Schnellstart

### Abhangigkeiten

Fugen Sie zu Ihrer `Cargo.toml` hinzu:

```toml
[dependencies]
micropqc = "0.1.0"
```

### Beispiel

```rust
use micropqc::{Kyber512, Kem};

// Schlusselpaar generieren
let mut rng = MyRng::new();
let (pk, sk) = Kyber512::keypair(&mut rng)?;

// Kapseln
let (ct, ss) = Kyber512::encapsulate(&mut rng, &pk)?;

// Entkapseln
let ss2 = Kyber512::decapsulate(&ct, &sk)?;
assert_eq!(ss.as_ref(), ss2.as_ref());
```

## Feature-Flags

| Feature | Beschreibung | Standard |
|---------|--------------|----------|
| `kyber512` | Kyber-512 Sicherheitsstufe | Ja |
| `kyber768` | Kyber-768 Sicherheitsstufe | Nein |
| `kyber1024` | Kyber-1024 Sicherheitsstufe | Nein |
| `std` | Standardbibliothek aktivieren | Nein |

### Sicherheitsstufen wechseln

```toml
[dependencies]
micropqc = { version = "0.1.0", default-features = false, features = ["kyber768"] }
```

## Schlusselgroßen

| Parameter | Offentlicher Schlussel | Geheimer Schlussel | Chiffrat | Gemeinsames Geheimnis |
|-----------|------------------------|--------------------|----------|-----------------------|
| Kyber512 | 800 Bytes | 768 Bytes | 768 Bytes | 32 Bytes |
| Kyber768 | 1184 Bytes | 1152 Bytes | 1088 Bytes | 32 Bytes |
| Kyber1024 | 1568 Bytes | 1536 Bytes | 1568 Bytes | 32 Bytes |

## Sicherheitsstufen

- **Kyber512**: NIST-Sicherheitsstufe 1 (vergleichbar mit AES-128)
- **Kyber768**: NIST-Sicherheitsstufe 3 (vergleichbar mit AES-192)
- **Kyber1024**: NIST-Sicherheitsstufe 5 (vergleichbar mit AES-256)

## Plattformunterstutzung

- x86_64
- ARM Cortex-M
- RISC-V
- WebAssembly (wasm32)

## Kompilieren

```bash
# Standard-Kompilierung
cargo build --release

# Tests ausfuhren
cargo test

# Dokumentation erstellen
cargo doc --no-deps
```

## Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).

## Mitwirken

Issues und Pull Requests sind willkommen!

## Danksagung

- Basiert auf der [Kyber](https://pq-crystals.org/kyber/)-Referenzimplementierung
- Dank an das NIST Post-Quantum Cryptography Standardization Projekt

---

**Hinweis**: Dieses Projekt befindet sich in einer fruhen Entwicklungsphase. APIs konnen sich andern. Bitte testen Sie grundlich vor dem Einsatz in der Produktion.
