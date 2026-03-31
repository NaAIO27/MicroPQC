//! Polynomial operations for Kyber

use crate::{KYBER_N, KYBER_Q};
use crate::{barrett_reduce, freeze};
use crate::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A polynomial with coefficients in Z_q.
/// 
/// Represents a polynomial of degree less than KYBER_N (256) with coefficients
/// in the range [0, KYBER_Q-1] where KYBER_Q = 3329.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Poly {
    /// Polynomial coefficients (256 coefficients)
    pub coeffs: [i16; KYBER_N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0; KYBER_N] }
    }
}

impl Poly {
    /// Create a new zero polynomial
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply Barrett reduction to all coefficients
    #[inline(always)]
    pub fn reduce(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = barrett_reduce(*coeff as i64) as i16;
        }
    }

    /// Reduce all coefficients to the canonical range [0, Q-1]
    #[inline(always)]
    pub fn freeze(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = freeze(*coeff as i32) as i16;
        }
    }

    /// Add another polynomial to this one in place
    #[inline(always)]
    pub fn add_assign(&mut self, other: &Poly) {
        for (a, b) in self.coeffs.iter_mut().zip(other.coeffs.iter()) {
            *a = a.wrapping_add(*b);
        }
    }

    /// Subtract another polynomial from this one in place
    #[inline(always)]
    pub fn sub_assign(&mut self, other: &Poly) {
        for (a, b) in self.coeffs.iter_mut().zip(other.coeffs.iter()) {
            *a = a.wrapping_sub(*b);
        }
    }

    /// Deserialize a polynomial from a byte array (384 bytes)
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 384 {
            return Err(Error::InvalidInput);
        }
        let mut p = Self::new();
        
        for i in 0..KYBER_N / 2 {
            let b0 = bytes[3 * i] as i16;
            let b1 = bytes[3 * i + 1] as i16;
            let b2 = bytes[3 * i + 2] as i16;
            
            p.coeffs[2 * i] = ((b0 >> 0) | (b1 << 8)) & 0xFFF;
            p.coeffs[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) & 0xFFF;
        }
        Ok(p)
    }

    /// Serialize the polynomial to a byte array (384 bytes)
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

    /// Compress the polynomial using d bits per coefficient
    /// 
    /// Returns a byte array containing the compressed coefficients.
    /// The actual size depends on d: 128 bytes for d=4, 160 for d=5, 320 for d=10, 352 for d=11.
    pub fn compress(&self, d: u32) -> Result<[u8; 352], Error> {
        let mut bytes = [0u8; 352];
        let shift = 1i64 << d;
        
        match d {
            4 => {
                for i in 0..KYBER_N / 2 {
                    let mut t0 = self.coeffs[2 * i] as i64;
                    let mut t1 = self.coeffs[2 * i + 1] as i64;
                    t0 = ((t0 * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) & ((shift - 1) as i64);
                    t1 = ((t1 * shift + KYBER_Q as i64 / 2) / KYBER_Q as i64) & ((shift - 1) as i64);
                    bytes[i] = (t0 | (t1 << 4)) as u8;
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
            _ => return Err(Error::InvalidInput),
        }
        Ok(bytes)
    }

    /// Decompress a polynomial from a byte array using d bits per coefficient
    pub fn decompress(&mut self, bytes: &[u8], d: u32) -> Result<(), Error> {
        let shift = (1i64 << d) as i64;
        
        match d {
            4 => {
                let required_len = KYBER_N / 2;
                if bytes.len() < required_len {
                    return Err(Error::InvalidInput);
                }
                for i in 0..KYBER_N / 2 {
                    let t = bytes[i];
                    self.coeffs[2 * i] = ((((t & 0xF) as i64) * KYBER_Q as i64 + shift / 2) / shift) as i16;
                    self.coeffs[2 * i + 1] = ((((t >> 4) as i64) * KYBER_Q as i64 + shift / 2) / shift) as i16;
                }
            }
            5 => {
                let required_len = 5 * KYBER_N / 8;
                if bytes.len() < required_len {
                    return Err(Error::InvalidInput);
                }
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
                let required_len = 5 * KYBER_N / 4;
                if bytes.len() < required_len {
                    return Err(Error::InvalidInput);
                }
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
                let required_len = 11 * KYBER_N / 8;
                if bytes.len() < required_len {
                    return Err(Error::InvalidInput);
                }
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
            _ => return Err(Error::InvalidInput),
        }
        Ok(())
    }

    /// Convert a message to polynomial representation
    pub fn to_msg(msg: &mut [u8; 32]) {
        for i in 0..32 {
            let mut t = 0i64;
            for j in 0..8 {
                t += ((msg[i] >> j) & 1) as i64 * ((KYBER_Q + 1) / 2) as i64;
            }
            msg[i] = ((t + KYBER_Q as i64 / 2) / KYBER_Q as i64) as u8;
        }
    }

    /// Convert polynomial to message representation
    pub fn from_msg(&mut self, msg: &[u8; 32]) {
        for i in 0..32 {
            for j in 0..8 {
                let mask = -(((msg[i] >> j) & 1) as i16);
                self.coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2) as i16;
            }
        }
    }
    
    /// Extract a 32-byte message from the polynomial coefficients
    /// 
    /// Each coefficient is decoded to a bit: 1 if closer to (q+1)/2, 0 if closer to 0
    pub fn extract_msg(&self) -> [u8; 32] {
        let mut msg = [0u8; 32];
        for i in 0..32 {
            let mut b = 0u8;
            for j in 0..8 {
                let mut t = self.coeffs[8 * i + j] as i32;
                t = ((t % KYBER_Q) + KYBER_Q) % KYBER_Q;
                if t > (KYBER_Q - 1) / 2 {
                    b |= 1 << j;
                }
            }
            msg[i] = b;
        }
        msg
    }
}

/// A vector of K polynomials
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PolyVec<const K: usize> {
    /// Array of K polynomials
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
    /// Create a new vector of zero polynomials
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply Barrett reduction to all polynomials
    #[inline(always)]
    pub fn reduce(&mut self) {
        for p in &mut self.vec {
            p.reduce();
        }
    }

    /// Add another polynomial vector to this one in place
    #[inline(always)]
    pub fn add_assign(&mut self, other: &PolyVec<K>) {
        for (a, b) in self.vec.iter_mut().zip(other.vec.iter()) {
            a.add_assign(b);
        }
    }

    /// Deserialize from a byte array
    pub fn from_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        const POLYBYTES: usize = 384;
        let required_len = K * POLYBYTES;
        if bytes.len() < required_len {
            return Err(Error::InvalidInput);
        }
        for (i, p) in self.vec.iter_mut().enumerate() {
            *p = Poly::from_bytes(&bytes[i * POLYBYTES..(i + 1) * POLYBYTES])?;
        }
        Ok(())
    }

    /// Serialize to a byte array
    pub fn to_bytes_into(&self, out: &mut [u8]) {
        for (i, p) in self.vec.iter().enumerate() {
            out[i * 384..(i + 1) * 384].copy_from_slice(&p.to_bytes());
        }
    }
}

/// Polynomial vector with 2 polynomials
pub type PolyVec2 = PolyVec<2>;
/// Polynomial vector with 3 polynomials
pub type PolyVec3 = PolyVec<3>;
/// Polynomial vector with 4 polynomials
pub type PolyVec4 = PolyVec<4>;
