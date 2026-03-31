//! Cryptographically secure random number generator trait for no_std environments

/// Trait for cryptographically secure random number generators
pub trait CryptoRng {
    /// Fill the destination buffer with random bytes
    fn fill_bytes(&mut self, dest: &mut [u8]);
    
    /// Try to fill the destination buffer with random bytes
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Error type for random number generation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Random number generation error
    RngError,
}

#[cfg(feature = "std")]
mod std_rng {
    use super::CryptoRng;
    use rand::RngCore;
    
    /// Standard random number generator wrapper using rand crate
    pub struct StdRng {
        inner: rand::rngs::ThreadRng,
    }
    
    impl StdRng {
        /// Create a new standard RNG instance
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

/// Fixed RNG for testing purposes - produces deterministic output
/// 
/// # Security Warning
/// 
/// This RNG is **NOT** cryptographically secure and should **ONLY** be used
/// for testing purposes. Using this in production will result in 
/// complete compromise of cryptographic security.
#[cfg(test)]
pub struct FixedRng {
    /// Fixed data buffer
    pub data: [u8; 64],
    /// Current position in the buffer
    pub pos: usize,
}

#[cfg(test)]
impl FixedRng {
    /// Create a new fixed RNG with the given data
    pub fn new(data: [u8; 64]) -> Self {
        Self { data, pos: 0 }
    }
}

#[cfg(test)]
impl CryptoRng for FixedRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.data[self.pos % 64];
            self.pos = (self.pos + 1) % 64;
        }
    }
}

#[cfg(test)]
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
