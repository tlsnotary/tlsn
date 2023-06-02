//! A library for computing different kinds of hash functions in a 2PC setting

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

#[cfg(feature = "ghash")]
/// This module implements [UniversalHash] for Ghash
pub mod ghash;

use async_trait::async_trait;
use std::fmt::Debug;
use tracing::instrument;

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
/// Errors for [UniversalHash]
pub enum UniversalHashError {
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid key length, expected {0}, got {1}")]
    KeyLengthError(usize, usize),
    #[error("Invalid input length: {0}")]
    InputLengthError(usize),
    #[error(transparent)]
    ShareConversionError(#[from] mpc_share_conversion::ShareConversionError),
}

#[async_trait]
/// A trait supporting different kinds of hash functions
pub trait UniversalHash: Send + Debug {
    /// Set the key for the hash function
    ///
    /// * `key` - Key to use for the hash function
    #[instrument(level = "trace")]
    async fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError>;

    /// Computes hash of the input, padding the input to the block size
    /// if needed.
    ///
    /// * `input` - Input to hash
    #[instrument(level = "trace")]
    async fn finalize(&mut self, input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError>;
}
