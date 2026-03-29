//! Error types for MicroPQC

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidCiphertext,
    DecapsulationFailed,
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
