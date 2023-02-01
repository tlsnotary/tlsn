#[cfg(feature = "ghash")]
pub mod ghash;

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum UniversalHashError {
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid key length, expected {0}, got {1}")]
    KeyLengthError(usize, usize),
    #[error("Invalid input length: {0}")]
    InputLengthError(usize),
    #[error("Share Conversion Error: {0}")]
    ShareConversionError(#[from] share_conversion_aio::ShareConversionError),
}

#[async_trait]
pub trait UniversalHash {
    /// Size of the key in bytes
    const KEY_SIZE: usize;
    /// Size of the block in bytes
    const BLOCK_SIZE: usize;

    /// Set the key for the hash function
    ///
    /// * `key` - Key to use for the hash function
    async fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError>;

    /// Computes hash of the input, padding the input to the block size
    /// if needed.
    ///
    /// * `input` - Input to hash
    async fn finalize(&mut self, input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError>;
}
