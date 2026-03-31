//! Number Theoretic Transform (NTT) operations for Kyber

use crate::{montgomery_reduce, barrett_reduce, KYBER_N, KYBER_Q};
use crate::poly::Poly;

/// Precomputed twiddle factors for forward NTT
pub const ZETAS: [i32; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -44,
    -839, -174, 277, -164, 1103, 847, 1228, -1363,
    -1660, -1181, 843, 1027, 682, -1607, -859, -163,
    1556, -1349, 1117, 539, -1670, 745, -607, 1658,
    -1589, 1604, -1622, 1177, -1641, 1308, -1635, -1629,
    -1619, -1603, 1387, -1591, -1585, -1579, -1567, -1561,
    -1549, -1543, -1531, -1519, -1507, -1495, -1489, -1477,
    -1465, -1453, -1441, -1429, -1417, -1405, -1393, -1381,
    -1369, -1357, -1345, -1333, -1321, -1309, -1297, -1285,
    -1273, -1261, -1249, -1237, -1225, -1213, -1201, -1189,
    -1177, -1165, -1153, -1141, -1129, -1117, -1105, -1093,
    -1081, -1069, -1057, -1045, -1033, -1021, -1009, -997,
    -985, -973, -961, -949, -937, -925, -913, -901,
    -889, -877, -865, -853, -841, -829, -817, -805,
];

/// Precomputed twiddle factors for inverse NTT
pub const ZETAS_INV: [i32; 128] = [
    1701, 1807, 1460, 2371, 2338, 2344, 1840, 1867,
    1787, 1833, 2520, 1520, 1839, 2500, 2519, 2481,
    2525, 2493, 2527, 2499, 2511, 2503, 2517, 2507,
    2519, 2509, 2515, 2505, 2513, 2501, 2519, 2503,
    2517, 2507, 2519, 2509, 2515, 2505, 2513, 2501,
    2519, 2503, 2517, 2507, 2519, 2509, 2515, 2505,
    2513, 2501, 2519, 2503, 2517, 2507, 2519, 2509,
    2515, 2505, 2513, 2501, 2519, 2503, 2517, 2507,
    2519, 2509, 2515, 2505, 2513, 2501, 2519, 2503,
    2517, 2507, 2519, 2509, 2515, 2505, 2513, 2501,
    2519, 2503, 2517, 2507, 2519, 2509, 2515, 2505,
    2513, 2501, 2519, 2503, 2517, 2507, 2519, 2509,
    2515, 2505, 2513, 2501, 2519, 2503, 2517, 2507,
    2519, 2509, 2515, 2505, 2513, 2501, 2519, 2503,
    2517, 2507, 2519, 2509, 2515, 2505, 2513, 2501,
    2519, 2503, 2517, 2507, 2519, 2509, 2515, 2505,
];

#[inline(always)]
fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce((a as i64) * (b as i64))
}

#[inline(always)]
fn fqmul_i16(a: i16, b: i32) -> i16 {
    montgomery_reduce((a as i64) * (b as i64)) as i16
}

impl Poly {
    /// Compute the Number Theoretic Transform (NTT) in place
    /// 
    /// Transforms the polynomial to the NTT domain for efficient multiplication
    pub fn ntt(&mut self) {
        let mut len = 128;
        let mut k = 1;
        
        while len >= 2 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS[k];
                k += 1;
                
                for j in start..start + len {
                    let t = fqmul(self.coeffs[j + len] as i32, zeta);
                    self.coeffs[j + len] = ((self.coeffs[j] as i32 - t).rem_euclid(KYBER_Q)) as i16;
                    self.coeffs[j] = ((self.coeffs[j] as i32 + t).rem_euclid(KYBER_Q)) as i16;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// Compute the inverse NTT and multiply by Montgomery factor
    /// 
    /// Transforms the polynomial back from NTT domain
    pub fn invntt_tomont(&mut self) {
        let mut len = 2;
        let mut k = 0;
        
        while len <= 128 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS_INV[k];
                k += 1;
                
                for j in start..start + len {
                    let t = self.coeffs[j] as i32;
                    let sum = t + self.coeffs[j + len] as i32;
                    self.coeffs[j] = barrett_reduce(sum as i64) as i16;
                    let diff = self.coeffs[j + len] as i32 - t;
                    self.coeffs[j + len] = fqmul_i16(diff as i16, zeta);
                }
                start += 2 * len;
            }
            len <<= 1;
        }

        const F: i32 = 1441;
        for coeff in self.coeffs.iter_mut() {
            *coeff = fqmul_i16(*coeff, F);
        }
    }

    /// Multiply two polynomials in NTT domain
    /// 
    /// Returns the product of self and other in NTT domain
    pub fn basemul(&self, other: &Poly, zeta: i32) -> Poly {
        let mut result = Poly::new();
        
        for i in (0..256).step_by(4) {
            let a0 = self.coeffs[i] as i64;
            let a1 = self.coeffs[i + 1] as i64;
            let b0 = other.coeffs[i] as i64;
            let b1 = other.coeffs[i + 1] as i64;
            
            result.coeffs[i] = barrett_reduce(a0 * b0 + a1 * b1 * (zeta as i64)) as i16;
            result.coeffs[i + 1] = barrett_reduce(a0 * b1 + a1 * b0) as i16;
            
            let a2 = self.coeffs[i + 2] as i64;
            let a3 = self.coeffs[i + 3] as i64;
            let b2 = other.coeffs[i + 2] as i64;
            let b3 = other.coeffs[i + 3] as i64;
            
            result.coeffs[i + 2] = barrett_reduce(a2 * b2 + a3 * b3 * (zeta as i64)) as i16;
            result.coeffs[i + 3] = barrett_reduce(a2 * b3 + a3 * b2) as i16;
        }
        result
    }
}

/// Multiply and accumulate polynomial vectors in NTT domain
/// 
/// Computes a = sum(pv1[i] * pv2[i]) for all i
pub fn polyvec_basemul_acc_montgomery<const K: usize>(a: &mut Poly, pv1: &[Poly; K], pv2: &[Poly; K]) {
    a.coeffs.fill(0);
    
    for (p1, p2) in pv1.iter().zip(pv2.iter()) {
        for i in 0..KYBER_N / 4 {
            let zeta = ZETAS[64 + i] as i32;
            
            let a0 = p1.coeffs[4 * i] as i32;
            let a1 = p1.coeffs[4 * i + 1] as i32;
            let b0 = p2.coeffs[4 * i] as i32;
            let b1 = p2.coeffs[4 * i + 1] as i32;
            
            let t0 = fqmul(a0, b0);
            let t1 = fqmul(a1, b1);
            let t1z = fqmul(t1, zeta);
            a.coeffs[4 * i] = a.coeffs[4 * i].wrapping_add((t0 + t1z) as i16);
            
            let t2 = fqmul(a0, b1);
            let t3 = fqmul(a1, b0);
            a.coeffs[4 * i + 1] = a.coeffs[4 * i + 1].wrapping_add((t2 - t3) as i16);
            
            let a2 = p1.coeffs[4 * i + 2] as i32;
            let a3 = p1.coeffs[4 * i + 3] as i32;
            let b2 = p2.coeffs[4 * i + 2] as i32;
            let b3 = p2.coeffs[4 * i + 3] as i32;
            
            let t4 = fqmul(a2, b2);
            let t5 = fqmul(a3, b3);
            let t5z = fqmul(t5, -zeta);
            a.coeffs[4 * i + 2] = a.coeffs[4 * i + 2].wrapping_add((t4 + t5z) as i16);
            
            let t6 = fqmul(a2, b3);
            let t7 = fqmul(a3, b2);
            a.coeffs[4 * i + 3] = a.coeffs[4 * i + 3].wrapping_add((t6 - t7) as i16);
        }
    }

    a.reduce();
}
