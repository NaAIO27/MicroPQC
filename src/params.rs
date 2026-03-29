//! Kyber parameter definitions for different security levels

use crate::KYBER_N;

/// Trait defining Kyber parameters for different security levels.
/// 
/// Each Kyber variant (Kyber512, Kyber768, Kyber1024) implements this trait
/// with specific parameters that determine the security level and performance
/// characteristics of the algorithm.
pub trait KyberParams {
    /// Number of polynomials in the key (dimension parameter)
    const K: usize;
    /// Noise parameter for the first error distribution
    const ETA1: u32;
    /// Noise parameter for the second error distribution
    const ETA2: u32;
    /// Compression parameter for ciphertext polynomial u
    const DU: u32;
    /// Compression parameter for ciphertext polynomial v
    const DV: u32;
    
    /// Size of the public key in bytes
    const PUBLICKEYBYTES: usize;
    /// Size of the secret key in bytes
    const SECRETKEYBYTES: usize;
    /// Size of the ciphertext in bytes
    const CIPHERTEXTBYTES: usize;
    /// Size of the shared secret in bytes
    const SHAREDSECRETBYTES: usize;
    
    /// Size of symmetric data in bytes (hash output size)
    const SYMBYTES: usize = 32;
    /// Size of a polynomial in bytes (uncompressed)
    const POLYBYTES: usize = 384;
    /// Size of a compressed polynomial with DV bits per coefficient
    const POLYCOMPRESSEDBYTES_DV: usize;
    /// Size of a compressed polynomial with DU bits per coefficient
    const POLYCOMPRESSEDBYTES_DU: usize;
}

/// Kyber512 parameters (NIST Level 1 security, ~128-bit classical security)
pub struct Kyber512;

impl KyberParams for Kyber512 {
    const K: usize = 2;
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    
    const PUBLICKEYBYTES: usize = Self::K * Self::POLYBYTES + Self::SYMBYTES;
    const SECRETKEYBYTES: usize = Self::K * Self::POLYBYTES;
    const CIPHERTEXTBYTES: usize = Self::K * Self::POLYCOMPRESSEDBYTES_DU + Self::POLYCOMPRESSEDBYTES_DV;
    const SHAREDSECRETBYTES: usize = Self::SYMBYTES;
    
    const POLYCOMPRESSEDBYTES_DV: usize = (KYBER_N * Self::DV as usize + 7) / 8;
    const POLYCOMPRESSEDBYTES_DU: usize = (KYBER_N * Self::DU as usize + 7) / 8;
}

/// Kyber768 parameters (NIST Level 3 security, ~192-bit classical security)
pub struct Kyber768;

impl KyberParams for Kyber768 {
    const K: usize = 3;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    
    const PUBLICKEYBYTES: usize = Self::K * Self::POLYBYTES + Self::SYMBYTES;
    const SECRETKEYBYTES: usize = Self::K * Self::POLYBYTES;
    const CIPHERTEXTBYTES: usize = Self::K * Self::POLYCOMPRESSEDBYTES_DU + Self::POLYCOMPRESSEDBYTES_DV;
    const SHAREDSECRETBYTES: usize = Self::SYMBYTES;
    
    const POLYCOMPRESSEDBYTES_DV: usize = (KYBER_N * Self::DV as usize + 7) / 8;
    const POLYCOMPRESSEDBYTES_DU: usize = (KYBER_N * Self::DU as usize + 7) / 8;
}

/// Kyber1024 parameters (NIST Level 5 security, ~256-bit classical security)
pub struct Kyber1024;

impl KyberParams for Kyber1024 {
    const K: usize = 4;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 11;
    const DV: u32 = 5;
    
    const PUBLICKEYBYTES: usize = Self::K * Self::POLYBYTES + Self::SYMBYTES;
    const SECRETKEYBYTES: usize = Self::K * Self::POLYBYTES;
    const CIPHERTEXTBYTES: usize = Self::K * Self::POLYCOMPRESSEDBYTES_DU + Self::POLYCOMPRESSEDBYTES_DV;
    const SHAREDSECRETBYTES: usize = Self::SYMBYTES;
    
    const POLYCOMPRESSEDBYTES_DV: usize = (KYBER_N * Self::DV as usize + 7) / 8;
    const POLYCOMPRESSEDBYTES_DU: usize = (KYBER_N * Self::DU as usize + 7) / 8;
}

/// Default Kyber variant based on feature flags
#[cfg(feature = "kyber512")]
pub type DefaultKyber = Kyber512;

#[cfg(all(feature = "kyber768", not(feature = "kyber512")))]
pub type DefaultKyber = Kyber768;

#[cfg(all(feature = "kyber1024", not(any(feature = "kyber512", feature = "kyber768"))))]
pub type DefaultKyber = Kyber1024;

#[cfg(not(any(feature = "kyber512", feature = "kyber768", feature = "kyber1024")))]
pub type DefaultKyber = Kyber512;
