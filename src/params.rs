//! Kyber parameter definitions for different security levels

use crate::KYBER_N;

pub trait KyberParams {
    const K: usize;
    const ETA1: u32;
    const ETA2: u32;
    const DU: u32;
    const DV: u32;
    
    const PUBLICKEYBYTES: usize;
    const SECRETKEYBYTES: usize;
    const CIPHERTEXTBYTES: usize;
    const SHAREDSECRETBYTES: usize;
    
    const SYMBYTES: usize = 32;
    const POLYBYTES: usize = 384;
    const POLYCOMPRESSEDBYTES_DV: usize;
    const POLYCOMPRESSEDBYTES_DU: usize;
}

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

#[cfg(feature = "kyber512")]
pub type DefaultKyber = Kyber512;

#[cfg(all(feature = "kyber768", not(feature = "kyber512")))]
pub type DefaultKyber = Kyber768;

#[cfg(all(feature = "kyber1024", not(any(feature = "kyber512", feature = "kyber768"))))]
pub type DefaultKyber = Kyber1024;

#[cfg(not(any(feature = "kyber512", feature = "kyber768", feature = "kyber1024")))]
pub type DefaultKyber = Kyber512;
