//! Polynomial operations for Kyber

use crate::{KYBER_N, KYBER_Q};
use crate::{barrett_reduce, freeze};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Poly {
    pub coeffs: [i16; KYBER_N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0; KYBER_N] }
    }
}

impl Poly {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn reduce(&mut self) {
        for i in 0..KYBER_N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i] as i64) as i16;
        }
    }

    #[inline(always)]
    pub fn freeze(&mut self) {
        for i in 0..KYBER_N {
            self.coeffs[i] = freeze(self.coeffs[i] as i32) as i16;
        }
    }

    #[inline(always)]
    pub fn add_assign(&mut self, other: &Poly) {
        for i in 0..KYBER_N {
            self.coeffs[i] += other.coeffs[i];
        }
    }

    #[inline(always)]
    pub fn sub_assign(&mut self, other: &Poly) {
        for i in 0..KYBER_N {
            self.coeffs[i] -= other.coeffs[i];
        }
    }

    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 384);
        let mut p = Self::new();
        
        for i in 0..KYBER_N / 2 {
            let b0 = bytes[3 * i] as i16;
            let b1 = bytes[3 * i + 1] as i16;
            let b2 = bytes[3 * i + 2] as i16;
            
            p.coeffs[2 * i] = ((b0 >> 0) | (b1 << 8)) & 0xFFF;
            p.coeffs[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) & 0xFFF;
        }
        p
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 384] {
        let mut bytes = [0u8; 384];
        
        for i in 0..KYBER_N / 2 {
            let t0 = freeze(self.coeffs[2 * i] as i32) as u16;
            let t1 = freeze(self.coeffs[2 * i + 1] as i32) as u16;
            
            bytes[3 * i] = (t0 & 0xFF) as u8;
            bytes[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
            bytes[3 * i + 2] = ((t1 >> 4) & 0xFF) as u8;
        }
        bytes
    }

    pub fn compress(&self, d: u32) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        let shift = 1i64 << d;
        
        match d {
            4 => {
                for i in 0..KYBER_N / 2 {
                    let t0 = (((self.coeffs[2 * i] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8 & 0xF;
                    let t1 = (((self.coeffs[2 * i + 1] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8 & 0xF;
                    bytes[i] = t0 | (t1 << 4);
                }
            }
            5 => {
                let mut j = 0;
                for i in (0..KYBER_N).step_by(8) {
                    let t0 = (((self.coeffs[i] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    let t1 = (((self.coeffs[i+1] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    let t2 = (((self.coeffs[i+2] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    let t3 = (((self.coeffs[i+3] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    let t4 = (((self.coeffs[i+4] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    let t5 = (((self.coeffs[i+5] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    let t6 = (((self.coeffs[i+6] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    let t7 = (((self.coeffs[i+7] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
                    
                    bytes[j] = t0 | (t1 << 5);
                    bytes[j+1] = (t1 >> 3) | (t2 << 2) | (t3 << 7);
                    bytes[j+2] = (t3 >> 1) | (t4 << 4);
                    bytes[j+3] = (t4 >> 4) | (t5 << 1) | (t6 << 6);
                    bytes[j+4] = (t6 >> 2) | (t7 << 3);
                    j += 5;
                }
            }
            10 => {
                for i in 0..KYBER_N / 4 {
                    let t0 = (((self.coeffs[4*i] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t1 = (((self.coeffs[4*i+1] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t2 = (((self.coeffs[4*i+2] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t3 = (((self.coeffs[4*i+3] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    
                    bytes[5*i] = t0 as u8;
                    bytes[5*i+1] = ((t0 >> 8) | ((t1 & 0x3F) << 2)) as u8;
                    bytes[5*i+2] = ((t1 >> 6) | ((t2 & 0x0F) << 4)) as u8;
                    bytes[5*i+3] = ((t2 >> 4) | ((t3 & 0x03) << 6)) as u8;
                    bytes[5*i+4] = (t3 >> 2) as u8;
                }
            }
            11 => {
                for i in 0..KYBER_N / 8 {
                    let t0 = (((self.coeffs[8*i] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t1 = (((self.coeffs[8*i+1] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t2 = (((self.coeffs[8*i+2] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t3 = (((self.coeffs[8*i+3] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t4 = (((self.coeffs[8*i+4] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t5 = (((self.coeffs[8*i+5] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t6 = (((self.coeffs[8*i+6] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    let t7 = (((self.coeffs[8*i+7] as i64) * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u16;
                    
                    bytes[11*i] = t0 as u8;
                    bytes[11*i+1] = ((t0 >> 8) | ((t1 & 0x1F) << 3)) as u8;
                    bytes[11*i+2] = ((t1 >> 5) | ((t2 & 0x03) << 6)) as u8;
                    bytes[11*i+3] = ((t2 >> 2) & 0xFF) as u8;
                    bytes[11*i+4] = ((t2 >> 10) | ((t3 & 0x0F) << 1)) as u8;
                    bytes[11*i+5] = ((t3 >> 4) | ((t4 & 0x01) << 4)) as u8;
                    bytes[11*i+6] = ((t4 >> 1) & 0xFF) as u8;
                    bytes[11*i+7] = ((t4 >> 9) | ((t5 & 0x3F) << 2)) as u8;
                    bytes[11*i+8] = ((t5 >> 6) | ((t6 & 0x07) << 5)) as u8;
                    bytes[11*i+9] = ((t6 >> 3) & 0xFF) as u8;
                    bytes[11*i+10] = t7 as u8;
                }
            }
            _ => panic!("Unsupported compression level"),
        }
        bytes
    }

    pub fn decompress(&mut self, bytes: &[u8], d: u32) {
        let shift = (1i64 << d) as i64;
        
        match d {
            4 => {
                for i in 0..KYBER_N / 2 {
                    let t = bytes[i];
                    self.coeffs[2 * i] = ((((t & 0xF) as i64) * KYBER_Q as i64 + shift / 2) / shift) as i16;
                    self.coeffs[2 * i + 1] = ((((t >> 4) as i64) * KYBER_Q as i64 + shift / 2) / shift) as i16;
                }
            }
            5 => {
                let mut j = 0;
                for i in (0..KYBER_N).step_by(8) {
                    let t = [bytes[j], bytes[j+1], bytes[j+2], bytes[j+3], bytes[j+4]];
                    self.coeffs[i] = (((t[0] & 0x1F) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    self.coeffs[i+1] = ((((t[0] >> 5) | ((t[1] & 0x03) << 3)) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    self.coeffs[i+2] = ((((t[1] >> 2) & 0x1F) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    self.coeffs[i+3] = ((((t[1] >> 7) | ((t[2] & 0x0F) << 1)) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    self.coeffs[i+4] = ((((t[2] >> 4) | ((t[3] & 0x01) << 4)) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    self.coeffs[i+5] = ((((t[3] >> 1) & 0x1F) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    self.coeffs[i+6] = ((((t[3] >> 6) | ((t[4] & 0x07) << 2)) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    self.coeffs[i+7] = (((t[4] >> 3) as i64 * KYBER_Q as i64 + 16) >> 5) as i16;
                    j += 5;
                }
            }
            10 => {
                for i in 0..KYBER_N / 4 {
                    let t = [
                        bytes[5*i] as u16,
                        bytes[5*i+1] as u16,
                        bytes[5*i+2] as u16,
                        bytes[5*i+3] as u16,
                        bytes[5*i+4] as u16,
                    ];
                    self.coeffs[4*i] = (((t[0] | ((t[1] & 0x03) << 8)) as i64 * KYBER_Q as i64 + 512) >> 10) as i16;
                    self.coeffs[4*i+1] = ((((t[1] >> 2) | ((t[2] & 0x0F) << 6)) as i64 * KYBER_Q as i64 + 512) >> 10) as i16;
                    self.coeffs[4*i+2] = ((((t[2] >> 4) | ((t[3] & 0x3F) << 4)) as i64 * KYBER_Q as i64 + 512) >> 10) as i16;
                    self.coeffs[4*i+3] = ((((t[3] >> 6) | (t[4] << 2)) as i64 * KYBER_Q as i64 + 512) >> 10) as i16;
                }
            }
            11 => {
                for i in 0..KYBER_N / 8 {
                    let t: [u16; 11] = [
                        bytes[11*i] as u16, bytes[11*i+1] as u16, bytes[11*i+2] as u16,
                        bytes[11*i+3] as u16, bytes[11*i+4] as u16, bytes[11*i+5] as u16,
                        bytes[11*i+6] as u16, bytes[11*i+7] as u16, bytes[11*i+8] as u16,
                        bytes[11*i+9] as u16, bytes[11*i+10] as u16,
                    ];
                    self.coeffs[8*i] = (((t[0] | ((t[1] & 0x07) << 8)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                    self.coeffs[8*i+1] = ((((t[1] >> 3) | ((t[2] & 0x3F) << 5)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                    self.coeffs[8*i+2] = ((((t[2] >> 6) | (t[3] << 2) | ((t[4] & 0x01) << 10)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                    self.coeffs[8*i+3] = ((((t[4] >> 1) | ((t[5] & 0x0F) << 7)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                    self.coeffs[8*i+4] = ((((t[5] >> 4) | ((t[6] & 0x7F) << 4)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                    self.coeffs[8*i+5] = ((((t[6] >> 7) | (t[7] << 1) | ((t[8] & 0x03) << 9)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                    self.coeffs[8*i+6] = ((((t[8] >> 2) | ((t[9] & 0x1F) << 6)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                    self.coeffs[8*i+7] = ((((t[9] >> 5) | (t[10] << 3)) as i64 * KYBER_Q as i64 + 1024) >> 11) as i16;
                }
            }
            _ => panic!("Unsupported decompression level"),
        }
    }

    pub fn to_msg(msg: &mut [u8; 32]) {
        for i in 0..32 {
            let mut t = 0i64;
            for j in 0..8 {
                t += ((msg[i] >> j) & 1) as i64 * ((KYBER_Q + 1) / 2) as i64;
            }
            msg[i] = ((t + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
        }
    }

    pub fn from_msg(&mut self, msg: &[u8; 32]) {
        for i in 0..32 {
            for j in 0..8 {
                let mask = -(((msg[i] >> j) & 1) as i16);
                self.coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2) as i16;
            }
        }
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PolyVec<const K: usize> {
    pub vec: [Poly; K],
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::new()),
        }
    }
}

impl<const K: usize> PolyVec<K> {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn reduce(&mut self) {
        for p in &mut self.vec {
            p.reduce();
        }
    }

    #[inline(always)]
    pub fn add_assign(&mut self, other: &PolyVec<K>) {
        for (a, b) in self.vec.iter_mut().zip(other.vec.iter()) {
            a.add_assign(b);
        }
    }

    pub fn from_bytes(&mut self, bytes: &[u8]) {
        const POLYBYTES: usize = 384;
        for (i, p) in self.vec.iter_mut().enumerate() {
            *p = Poly::from_bytes(&bytes[i * POLYBYTES..(i + 1) * POLYBYTES]);
        }
    }

    pub fn to_bytes_into(&self, out: &mut [u8]) {
        for (i, p) in self.vec.iter().enumerate() {
            out[i * 384..(i + 1) * 384].copy_from_slice(&p.to_bytes());
        }
    }
}

pub type PolyVec2 = PolyVec<2>;
pub type PolyVec3 = PolyVec<3>;
pub type PolyVec4 = PolyVec<4>;
