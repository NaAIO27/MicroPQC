//! Cryptographically secure random number generator trait for no_std environments

pub trait CryptoRng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    RngError,
}

#[cfg(feature = "std")]
mod std_rng {
    use super::CryptoRng;
    use rand::RngCore;
    
    pub struct StdRng {
        inner: rand::rngs::ThreadRng,
    }
    
    impl StdRng {
        pub fn new() -> Self {
            Self {
                inner: rand::thread_rng(),
            }
        }
    }
    
    impl CryptoRng for StdRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.inner.fill_bytes(dest);
        }
    }
    
    impl Default for StdRng {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(feature = "std")]
pub use std_rng::StdRng;

pub struct FixedRng {
    pub data: [u8; 64],
    pub pos: usize,
}

impl FixedRng {
    pub fn new(data: [u8; 64]) -> Self {
        Self { data, pos: 0 }
    }
}

impl CryptoRng for FixedRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.data[self.pos % 64];
            self.pos = (self.pos + 1) % 64;
        }
    }
}

impl Default for FixedRng {
    fn default() -> Self {
        Self::new([0u8; 64])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fixed_rng() {
        let mut rng = FixedRng::new([42u8; 64]);
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 42));
    }
}
