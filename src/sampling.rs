//! Sampling functions for Kyber (Centered Binomial Distribution and rejection sampling)

use crate::KYBER_N;
use crate::poly::Poly;
use tiny_keccak::{Hasher, Keccak};

#[inline(always)]
fn load24(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
}

#[inline(always)]
fn load32(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16) | ((x[3] as u32) << 24)
}

impl Poly {
    /// Sample from centered binomial distribution with eta=2
    /// 
    /// Uses 128 bytes of random input to generate 256 coefficients
    pub fn cbd_eta2(&mut self, buf: &[u8; 128]) {
        for i in 0..KYBER_N / 8 {
            let t = load32(&buf[4 * i..]);
            let d = t & 0x55555555;
            let d = d.wrapping_add((t >> 1) & 0x55555555);
            
            for j in 0..8 {
                let a = ((d >> (4 * j)) & 0x3) as i16;
                let b = ((d >> (4 * j + 2)) & 0x3) as i16;
                self.coeffs[8 * i + j] = a - b;
            }
        }
    }

    /// Sample from centered binomial distribution with eta=3
    /// 
    /// Uses 192 bytes of random input to generate 256 coefficients
    pub fn cbd_eta3(&mut self, buf: &[u8; 192]) {
        for i in 0..KYBER_N / 4 {
            let t = load24(&buf[3 * i..]);
            let mut d = 0u32;
            
            for j in 0..3 {
                d += (t >> j) & 0x00249249;
            }
            
            for j in 0..4 {
                let a = ((d >> (6 * j)) & 0x7) as i16;
                let b = ((d >> (6 * j + 3)) & 0x7) as i16;
                self.coeffs[4 * i + j] = a - b;
            }
        }
    }

    /// Generate noise polynomial from seed using eta=2
    pub fn get_noise_eta2(&mut self, seed: &[u8], nonce: u8) {
        let mut buf = [0u8; 128];
        prf(&mut buf, seed, nonce);
        self.cbd_eta2(&buf);
    }

    /// Generate noise polynomial from seed with specified eta
    pub fn get_noise_eta1(&mut self, eta: u32, seed: &[u8], nonce: u8) {
        match eta {
            2 => {
                let mut buf = [0u8; 128];
                prf(&mut buf, seed, nonce);
                self.cbd_eta2(&buf);
            }
            3 => {
                let mut buf = [0u8; 192];
                prf(&mut buf, seed, nonce);
                self.cbd_eta3(&buf);
            }
            _ => panic!("Unsupported eta value"),
        }
    }

    /// Sample polynomial uniformly from seed using rejection sampling
    pub fn uniform(&mut self, seed: &[u8], nonce: u8) {
        let mut buf = [0u8; 512];
        let mut ctr = 0;
        let mut off = 0;
        
        xof(&mut buf, seed, nonce);
        
        while ctr < KYBER_N && off + 3 <= buf.len() {
            let val = buf[off] as u16 | ((buf[off + 1] as u16) << 8);
            let d1 = val & 0xFFF;
            let d2 = val >> 4 & 0xFFF;
            
            if d1 < 3329 {
                self.coeffs[ctr] = d1 as i16;
                ctr += 1;
            }
            
            if ctr < KYBER_N && d2 < 3329 {
                self.coeffs[ctr] = d2 as i16;
                ctr += 1;
            }
            off += 3;
            
            if off + 3 > buf.len() {
                off = 0;
                xof(&mut buf, seed, nonce.wrapping_add(1));
            }
        }
    }
}

fn prf(out: &mut [u8], seed: &[u8], nonce: u8) {
    let mut ext_seed = [0u8; 33];
    ext_seed[..32].copy_from_slice(seed);
    ext_seed[32] = nonce;
    shake256(out, &ext_seed);
}

fn xof(out: &mut [u8], seed: &[u8], nonce: u8) {
    let mut ext_seed = [0u8; 33];
    ext_seed[..32].copy_from_slice(seed);
    ext_seed[32] = nonce;
    shake256(out, &ext_seed);
}

/// SHAKE256 extendable output function
/// 
/// Implementation using tiny-keccak library for cryptographic security.
/// 
/// # Safety
/// 
/// This function will panic if `out` is empty. For security,
/// ensure the output buffer has sufficient length for your use case.
/// 
/// # Examples
/// 
/// ```
/// use micropqc::sampling::shake256;
/// 
/// let mut output = [0u8; 32];
/// shake256(&mut output, b"input data");
/// ```
pub fn shake256(out: &mut [u8], in_: &[u8]) {
    assert!(!out.is_empty(), "SHAKE256 output buffer must not be empty");
    
    use tiny_keccak::Shake;
    let mut shake = Shake::v256();
    shake.update(in_);
    shake.finalize(out);
}

/// SHA3-256 hash function
/// 
/// Implementation using tiny-keccak library for cryptographic security
pub fn sha3_256(out: &mut [u8; 32], in_: &[u8]) {
    let mut keccak = Keccak::v256();
    keccak.update(in_);
    keccak.finalize(out);
}

/// SHA3-512 hash function
/// 
/// Implementation using tiny-keccak library for cryptographic security
pub fn sha3_512(out: &mut [u8; 64], in_: &[u8]) {
    let mut keccak = Keccak::v512();
    keccak.update(in_);
    keccak.finalize(out);
}

/// Key derivation function using SHAKE256
pub fn kdf(out: &mut [u8], in_: &[u8]) {
    shake256(out, in_);
}
