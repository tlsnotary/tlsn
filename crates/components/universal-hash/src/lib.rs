//! A library for computing different kinds of hash functions in a 2PC setting.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

/// This module implements [UniversalHash] for Ghash.
#[cfg(feature = "ghash")]
pub mod ghash;

use async_trait::async_trait;

/// Errors for [UniversalHash].
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum UniversalHashError {
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid key length, expected {0}, got {1}")]
    KeyLengthError(usize, usize),
    #[error("Invalid input length: {0}")]
    InputLengthError(usize),
    #[error(transparent)]
    ShareConversionError(#[from] mpz_share_conversion::ShareConversionError),
}

#[async_trait]
/// A trait supporting different kinds of hash functions.
pub trait UniversalHash: Send {
    /// Sets the key for the hash function
    ///
    /// # Arguments
    ///
    /// * `key` - Key to use for the hash function.
    async fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError>;

    /// Performs any necessary one-time setup.
    async fn setup(&mut self) -> Result<(), UniversalHashError>;

    /// Preprocesses the hash function.
    async fn preprocess(&mut self) -> Result<(), UniversalHashError>;

    /// Computes hash of the input, padding the input to the block size
    /// if needed.
    ///
    /// # Arguments
    ///
    /// * `input` - Input to hash.
    async fn finalize(&mut self, input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError>;
}
