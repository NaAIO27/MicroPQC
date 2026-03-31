#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! MicroPQC - Post-Quantum Cryptography for Embedded Systems
//!
//! A `no_std` compatible implementation of post-quantum cryptographic algorithms
//! optimized for resource-constrained embedded devices.
//!
//! # Features
//!
//! - Kyber (NIST PQC standardized KEM)
//! - `no_std` compatible
//! - Constant-time operations
//! - Zeroization of sensitive data
//!
//! # Example
//!
//! ```ignore
//! use micropqc::{Kyber512, Kem};
//!
//! let mut rng = MyRng::new();
//! let (pk, sk) = Kyber512::keypair(&mut rng)?;
//! let (ss, ct) = Kyber512::encapsulate(&pk, &mut rng)?;
//! let ss2 = Kyber512::decapsulate(&ct, &sk)?;
//! assert_eq!(ss, ss2);
//! ```

pub mod params;
pub mod poly;
pub mod ntt;
pub mod sampling;
pub mod random;
pub mod kem;
pub mod error;

pub use params::KyberParams;
pub use kem::{Kem, Kyber512, Kyber768, Kyber1024};
pub use error::Error;
pub use random::CryptoRng;

/// Polynomial degree
pub const KYBER_N: usize = 256;
/// Prime modulus
pub const KYBER_Q: i32 = 3329;

pub(crate) const QINV: i32 = 582639265;

#[inline(always)]
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64).wrapping_mul(KYBER_Q as i64)) >> 32) as i32
}

#[inline(always)]
pub(crate) fn barrett_reduce(a: i64) -> i32 {
    const V: i64 = 20159;
    const KYBER_Q_I64: i64 = 3329;
    let t = ((a * V) + (1 << 25)) >> 26;
    (a - t * KYBER_Q_I64) as i32
}

#[inline(always)]
pub(crate) fn freeze(a: i32) -> i32 {
    let a = a.wrapping_rem(KYBER_Q);
    a.wrapping_add((a >> 31) & KYBER_Q)
}
