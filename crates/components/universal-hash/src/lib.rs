//! A library for computing different kinds of hash functions in a 2PC setting.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

/// This module implements [UniversalHash] for Ghash.
#[cfg(feature = "ghash")]
pub mod ghash;

use async_trait::async_trait;
use mpz_common::Context;

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
pub trait UniversalHash<Ctx: Context> {
    /// Sets the key for the hash function
    ///
    /// # Arguments
    ///
    /// * `key` - Key to use for the hash function.
    /// * `ctx` - The context for IO.
    async fn set_key(&mut self, key: Vec<u8>, ctx: &mut Ctx) -> Result<(), UniversalHashError>;

    /// Performs any necessary one-time setup.
    async fn setup(&mut self) -> Result<(), UniversalHashError>;

    /// Preprocesses the hash function.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), UniversalHashError>;

    /// Computes hash of the input, padding the input to the block size
    /// if needed.
    ///
    /// # Arguments
    ///
    /// * `input` - Input to hash.
    /// * `ctx` - The context for IO.
    async fn finalize(
        &mut self,
        input: Vec<u8>,
        ctx: &mut Ctx,
    ) -> Result<Vec<u8>, UniversalHashError>;
}
