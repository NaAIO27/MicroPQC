//! Sampling functions for Kyber (Centered Binomial Distribution and rejection sampling)

use crate::KYBER_N;
use crate::poly::Poly;

#[inline(always)]
fn load24(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
}

#[inline(always)]
fn load32(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16) | ((x[3] as u32) << 24)
}

impl Poly {
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

    pub fn get_noise_eta2(&mut self, seed: &[u8], nonce: u8) {
        let mut buf = [0u8; 128];
        prf(&mut buf, seed, nonce);
        self.cbd_eta2(&buf);
    }

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

pub fn shake256(out: &mut [u8], in_: &[u8]) {
    use crate::random::CryptoRng;
    
    #[cfg(feature = "std")]
    {
        use std::collections::hash_map::DefaultHasher;
        use core::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        in_.hash(&mut hasher);
        let hash = hasher.finish();
        
        let hash_bytes = hash.to_le_bytes();
        let mut state = [0u8; 32];
        state[..8].copy_from_slice(&hash_bytes);
        
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = state[i % 32].wrapping_add(i as u8);
        }
    }
    
    #[cfg(not(feature = "std"))]
    {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = in_.get(i % in_.len()).copied().unwrap_or(0).wrapping_add(i as u8);
        }
    }
}

pub fn sha3_256(out: &mut [u8; 32], in_: &[u8]) {
    #[cfg(feature = "std")]
    {
        use std::collections::hash_map::DefaultHasher;
        use core::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        in_.hash(&mut hasher);
        let hash = hasher.finish().to_le_bytes();
        
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = hash[i % 8].wrapping_add((i / 8) as u8);
        }
    }
    
    #[cfg(not(feature = "std"))]
    {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = in_.get(i % in_.len()).copied().unwrap_or(0);
        }
    }
}

pub fn sha3_512(out: &mut [u8; 64], in_: &[u8]) {
    #[cfg(feature = "std")]
    {
        use std::collections::hash_map::DefaultHasher;
        use core::hash::{Hash, Hasher};
        
        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        
        in_.hash(&mut hasher1);
        in_.hash(&mut hasher2);
        
        let hash1 = hasher1.finish().to_le_bytes();
        let hash2 = hasher2.finish().to_le_bytes();
        
        out[..8].copy_from_slice(&hash1);
        out[8..16].copy_from_slice(&hash2);
        
        for i in 16..64 {
            out[i] = out[i % 16].wrapping_add(i as u8);
        }
    }
    
    #[cfg(not(feature = "std"))]
    {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = in_.get(i % in_.len()).copied().unwrap_or(0);
        }
    }
}

pub fn kdf(out: &mut [u8], in_: &[u8]) {
    shake256(out, in_);
}
