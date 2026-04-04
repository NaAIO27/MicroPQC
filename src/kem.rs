//! Key Encapsulation Mechanism (KEM) implementation for Kyber

use crate::params::KyberParams;
use crate::poly::{Poly, PolyVec};
use crate::ntt::polyvec_basemul_acc_montgomery;
use crate::sampling::{sha3_256, sha3_512, kdf, shake256};
use crate::random::CryptoRng;
use crate::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub trait Kem {
    type PublicKey: AsRef<[u8]>;
    type SecretKey: AsRef<[u8]> + Zeroize;
    type Ciphertext: AsRef<[u8]>;
    type SharedSecret: AsRef<[u8]>;
    
    fn keypair<R: CryptoRng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), Error>;
    
    fn encapsulate<R: CryptoRng>(
        rng: &mut R,
        pk: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Error>;
    
    fn decapsulate(
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Error>;
}

macro_rules! impl_kyber {
    ($name:ident, $params:ty, $k:expr, $pk_size:expr, $sk_size:expr, $ct_size:expr) => {
        pub struct $name;
        
        impl Kem for $name {
            type PublicKey = KyberPublicKey<$pk_size>;
            type SecretKey = KyberSecretKey<{ $sk_size + $pk_size + 64 }>;
            type Ciphertext = KyberCiphertext<$ct_size>;
            type SharedSecret = KyberSharedSecret;
            
            fn keypair<R: CryptoRng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                
                let mut z = [0u8; 32];
                rng.fill_bytes(&mut z);
                
                let mut publickey = KyberPublicKey::<$pk_size>::default();
                let mut secretkey = KyberSecretKey::<{ $sk_size + $pk_size + 64 }>::default();
                
                let mut buf = [0u8; 64];
                sha3_512(&mut buf, &seed);
                
                let publicseed = &buf[0..32];
                let noiseseed = &buf[32..64];
                
                let mut a = PolyVec::<$k>::new();
                for i in 0..$k {
                    a.vec[i].uniform(publicseed, i as u8);
                }
                
                let mut skpv = PolyVec::<$k>::new();
                for i in 0..$k {
                    skpv.vec[i].get_noise_eta1(<$params>::ETA1, noiseseed, i as u8);
                    skpv.vec[i].ntt();
                }
                
                let mut e = PolyVec::<$k>::new();
                for i in 0..$k {
                    e.vec[i].get_noise_eta1(<$params>::ETA1, noiseseed, ($k + i) as u8);
                    e.vec[i].ntt();
                }
                
                let mut pkpv = PolyVec::<$k>::new();
                for i in 0..$k {
                    polyvec_basemul_acc_montgomery(&mut pkpv.vec[i], &a.vec, &skpv.vec);
                    pkpv.vec[i].add_assign(&e.vec[i]);
                    pkpv.vec[i].reduce();
                }
                
                for i in 0..$k {
                    skpv.vec[i].invntt_tomont();
                    skpv.vec[i].reduce();
                }
                
                let mut pk_bytes = [0u8; $k * 384];
                pkpv.to_bytes_into(&mut pk_bytes);
                publickey.bytes[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                publickey.bytes[pk_bytes.len()..pk_bytes.len() + 32].copy_from_slice(publicseed);
                
                let mut sk_bytes = [0u8; $k * 384];
                skpv.to_bytes_into(&mut sk_bytes);
                secretkey.bytes[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                
                secretkey.bytes[$sk_size..$sk_size + $pk_size].copy_from_slice(&publickey.bytes);
                
                let mut pk_hash = [0u8; 32];
                sha3_256(&mut pk_hash, &publickey.bytes);
                secretkey.bytes[$sk_size + $pk_size..$sk_size + $pk_size + 32].copy_from_slice(&pk_hash);
                
                secretkey.bytes[$sk_size + $pk_size + 32..].copy_from_slice(&z);
                
                buf.zeroize();
                seed.zeroize();
                z.zeroize();
                
                Ok((publickey, secretkey))
            }
            
            fn encapsulate<R: CryptoRng>(
                rng: &mut R,
                pk: &Self::PublicKey,
            ) -> Result<(Self::Ciphertext, Self::SharedSecret), Error> {
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);
                
                let mut h = [0u8; 32];
                sha3_256(&mut h, pk.as_ref());
                
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&m);
                combined[32..].copy_from_slice(&h);
                
                let mut kr = [0u8; 64];
                sha3_512(&mut kr, &combined);
                
                let k = &kr[..32];
                let r = &kr[32..];
                
                let pk_bytes = pk.as_ref();
                let publicseed = &pk_bytes[$k * 384..$k * 384 + 32];
                
                let ct_bytes = compute_ciphertext::<$k, $ct_size, $params>(publicseed, r, &m, pk_bytes)?;
                
                let mut ct = KyberCiphertext::<$ct_size>::default();
                ct.bytes.copy_from_slice(&ct_bytes);
                
                let mut shared_secret = KyberSharedSecret::default();
                shared_secret.bytes.copy_from_slice(k);
                
                Ok((ct, shared_secret))
            }
            
            fn decapsulate(
                ct: &Self::Ciphertext,
                sk: &Self::SecretKey,
            ) -> Result<Self::SharedSecret, Error> {
                let sk_bytes = sk.as_ref();
                
                let mut skpv = PolyVec::<$k>::new();
                skpv.from_bytes(&sk_bytes[..$k * 384])?;
                
                for i in 0..$k {
                    skpv.vec[i].ntt();
                }
                
                let pk_offset = $sk_size;
                let pk_bytes = &sk_bytes[pk_offset..pk_offset + $pk_size];
                
                let pk_hash_offset = pk_offset + $pk_size;
                let pk_hash = &sk_bytes[pk_hash_offset..pk_hash_offset + 32];
                
                let z_offset = pk_hash_offset + 32;
                let z = &sk_bytes[z_offset..z_offset + 32];
                
                let mut bp = PolyVec::<$k>::new();
                let mut offset = 0;
                for i in 0..$k {
                    let len = <$params>::POLYCOMPRESSEDBYTES_DU;
                    bp.vec[i].decompress(&ct.as_ref()[offset..offset + len], <$params>::DU)?;
                    offset += len;
                }
                
                let mut v = Poly::new();
                let v_len = <$params>::POLYCOMPRESSEDBYTES_DV;
                v.decompress(&ct.as_ref()[offset..offset + v_len], <$params>::DV)?;
                
                for i in 0..$k {
                    bp.vec[i].ntt();
                }
                
                let mut mp = Poly::new();
                polyvec_basemul_acc_montgomery(&mut mp, &skpv.vec, &bp.vec);
                mp.invntt_tomont();
                mp.reduce();
                
                v.sub_assign(&mp);
                v.freeze();
                
                let mut m = v.extract_msg();
                
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&m);
                combined[32..].copy_from_slice(pk_hash);
                
                let mut kr = [0u8; 64];
                sha3_512(&mut kr, &combined);
                
                let k = &kr[..32];
                let r = &kr[32..];
                
                let publicseed = &pk_bytes[$k * 384..$k * 384 + 32];
                
                let ct_cmp = compute_ciphertext::<$k, $ct_size, $params>(publicseed, r, &m, pk_bytes)?;
                
                let ct_bytes = ct.as_ref();
                let valid = ct_bytes.len() == $ct_size && 
                    ct_bytes.iter().zip(ct_cmp.iter()).all(|(a, b)| a == b);
                
                let mut shared_secret = KyberSharedSecret::default();
                
                if valid {
                    shared_secret.bytes.copy_from_slice(k);
                } else {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(z);
                    buf[32..].copy_from_slice(&ct_bytes[..32.min(ct_bytes.len())]);
                    
                    let mut fake_k = [0u8; 32];
                    sha3_256(&mut fake_k, &buf);
                    shared_secret.bytes.copy_from_slice(&fake_k);
                }
                
                m.zeroize();
                kr.zeroize();
                
                Ok(shared_secret)
            }
        }
    };
}

fn compute_ciphertext<const K: usize, const CT_SIZE: usize, P: KyberParams>(
    publicseed: &[u8],
    r: &[u8],
    m: &[u8; 32],
    pk_bytes: &[u8],
) -> Result<[u8; CT_SIZE], Error> {
    let mut a = PolyVec::<K>::new();
    for i in 0..K {
        a.vec[i].uniform(publicseed, i as u8);
    }
    
    let mut sp = PolyVec::<K>::new();
    for i in 0..K {
        sp.vec[i].get_noise_eta1(P::ETA2, r, i as u8);
        sp.vec[i].ntt();
    }
    
    let mut ep = PolyVec::<K>::new();
    for i in 0..K {
        ep.vec[i].get_noise_eta1(P::ETA2, r, (K + i) as u8);
        ep.vec[i].ntt();
    }
    
    let mut bp = PolyVec::<K>::new();
    for i in 0..K {
        polyvec_basemul_acc_montgomery(&mut bp.vec[i], &a.vec, &sp.vec);
        bp.vec[i].add_assign(&ep.vec[i]);
        bp.vec[i].reduce();
    }
    
    if pk_bytes.len() < K * 384 {
        return Err(Error::InvalidPublicKey);
    }

    let mut pkpv = PolyVec::<K>::new();
    pkpv.from_bytes(&pk_bytes[..K * 384])?;
    
    let mut v = Poly::new();
    polyvec_basemul_acc_montgomery(&mut v, &pkpv.vec, &sp.vec);
    v.invntt_tomont();
    v.reduce();
    
    let mut epp = Poly::new();
    epp.get_noise_eta1(P::ETA2, r, (2 * K) as u8);
    v.add_assign(&epp);
    
    let mut mp = Poly::new();
    mp.from_msg(m);
    v.add_assign(&mp);
    v.reduce();
    
    for i in 0..K {
        bp.vec[i].invntt_tomont();
        bp.vec[i].reduce();
    }
    
    let mut ct = [0u8; CT_SIZE];
    let mut offset = 0;
    for i in 0..K {
        let compressed = bp.vec[i].compress(P::DU)?;
        let len = P::POLYCOMPRESSEDBYTES_DU;
        ct[offset..offset + len].copy_from_slice(&compressed[..len]);
        offset += len;
    }
    
    let v_compressed = v.compress(P::DV)?;
    let v_len = P::POLYCOMPRESSEDBYTES_DV;
    ct[offset..offset + v_len].copy_from_slice(&v_compressed[..v_len]);
    
    Ok(ct)
}

impl_kyber!(Kyber512, crate::params::Kyber512, 2, 800, 768, 768);
impl_kyber!(Kyber768, crate::params::Kyber768, 3, 1184, 1152, 1088);
impl_kyber!(Kyber1024, crate::params::Kyber1024, 4, 1568, 1536, 1568);

#[derive(Clone, Debug)]
pub struct KyberPublicKey<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Default for KyberPublicKey<N> {
    fn default() -> Self {
        Self { bytes: [0u8; N] }
    }
}

impl<const N: usize> AsRef<[u8]> for KyberPublicKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Default for KyberSecretKey<N> {
    fn default() -> Self {
        Self { bytes: [0u8; N] }
    }
}

impl<const N: usize> AsRef<[u8]> for KyberSecretKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug)]
pub struct KyberCiphertext<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Default for KyberCiphertext<N> {
    fn default() -> Self {
        Self { bytes: [0u8; N] }
    }
}

impl<const N: usize> AsRef<[u8]> for KyberCiphertext<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KyberSharedSecret {
    bytes: [u8; 32],
}

impl Default for KyberSharedSecret {
    fn default() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

impl AsRef<[u8]> for KyberSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::FixedRng;
    
    #[test]
    fn test_kyber512_keypair() {
        let mut rng = FixedRng::new([1u8; 64]);
        let result = Kyber512::keypair(&mut rng);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_kyber512_encapsulate_decapsulate() {
        let mut rng = FixedRng::new([1u8; 64]);
        let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
        
        let mut rng2 = FixedRng::new([2u8; 64]);
        let (ct, ss1) = Kyber512::encapsulate(&mut rng2, &pk).unwrap();
        
        let ss2 = Kyber512::decapsulate(&ct, &sk).unwrap();
        
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }
}
