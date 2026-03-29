//! Error types for MicroPQC

/// Error type for Kyber operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid input data provided
    InvalidInput,
    /// Invalid public key format or value
    InvalidPublicKey,
    /// Invalid secret key format or value
    InvalidSecretKey,
    /// Invalid ciphertext format or value
    InvalidCiphertext,
    /// Decapsulation failed - ciphertext may be corrupted
    DecapsulationFailed,
    /// Random number generation error
    RandomError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidSecretKey => write!(f, "Invalid secret key"),
            Error::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            Error::DecapsulationFailed => write!(f, "Decapsulation failed"),
            Error::RandomError => write!(f, "Random number generation error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
