//! This crate provides implementations of 2PC AEADs for authenticated encryption with
//! a shared key.
//!
//! There are two distinct roles, the `AEADLeader` and the `AEADFollower`.
//!
//! Both parties can work together to encrypt and decrypt messages where the plaintext
//! is visible to both.
//!
//! Alternatively, they can choose to encrypt or decrypt where only the leader
//! sees the plaintext message.

pub mod aes_gcm;
pub mod msg;

pub use msg::AeadMessage;

use async_trait::async_trait;

use block_cipher::BlockCipherLabels;
use mpc_core::garble::{ActiveLabels, FullLabels};
use tlsn_stream_cipher::StreamCipherLabels;
use utils_aio::Channel;

pub type AeadChannel = Box<dyn Channel<AeadMessage, Error = std::io::Error> + Send>;

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("BlockCipherError: {0}")]
    BlockCipherError(#[from] block_cipher::BlockCipherError),
    #[error("StreamCipherError: {0}")]
    StreamCipherError(#[from] tlsn_stream_cipher::StreamCipherError),
    #[error("UniversalHashError: {0}")]
    UniversalHashError(#[from] tlsn_universal_hash::UniversalHashError),
    #[error("Corrupted Tag")]
    CorruptedTag,
    #[error("Validation Error: {0}")]
    ValidationError(String),
    #[error("Unexpected Message: {0:?}")]
    UnexpectedMessage(AeadMessage),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

#[async_trait]
pub trait AeadLeader {
    /// Sets the key input labels for the AEAD.
    ///
    /// * `labels` - The labels to use for the key input.
    async fn set_keys(&mut self, labels: AeadLabels) -> Result<(), AeadError>;

    /// Encrypts a plaintext message, returning the ciphertext and tag.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for encryption.
    /// * `plaintext` - The plaintext to encrypt.
    /// * `aad` - Optional additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn encrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError>;

    /// Encrypts a plaintext message, hiding it from `AeadFollower`, returning the ciphertext and tag.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for encryption.
    /// * `plaintext` - The plaintext to encrypt.
    /// * `aad` - Optional additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypts a ciphertext message, returning the plaintext to both parties.
    ///
    /// This method checks the authenticity of the ciphertext, tag and additional data.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for decryption.
    /// * `ciphertext` - The ciphertext and tag to authenticate and decrypt.
    /// * `aad` - Additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn decrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypts a ciphertext message, returning the plaintext only to the `AeadLeader`.
    ///
    /// This method checks the authenticity of the ciphertext, tag and additional data.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for decryption.
    /// * `ciphertext` - The ciphertext and tag to authenticate and decrypt.
    /// * `aad` - Additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError>;
}

#[async_trait]
pub trait AeadFollower {
    /// Sets the key input labels for the AEAD.
    ///
    /// * `labels` - The labels to use for the key input.
    async fn set_keys(&mut self, labels: AeadLabels) -> Result<(), AeadError>;

    /// Encrypts a plaintext message returning the ciphertext and tag.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for encryption.
    /// * `plaintext` - The length of the plaintext to encrypt.
    /// * `aad` - Optional additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn encrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError>;

    /// Encrypts a plaintext message provided by the `AeadLeader`, returning
    /// the ciphertext and tag.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for encryption.
    /// * `plaintext_len` - The length of the plaintext to encrypt.
    /// * `aad` - Optional additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext_len: usize,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypts a ciphertext message, returning the plaintext to both parties.
    ///
    /// This method checks the authenticity of the ciphertext, tag and additional data.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for decryption.
    /// * `ciphertext` - The ciphertext and tag to authenticate and decrypt.
    /// * `aad` - Additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn decrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypts a ciphertext message, returning the plaintext only to the `AeadLeader`.
    ///
    /// This method checks the authenticity of the ciphertext, tag and additional data.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for decryption.
    /// * `ciphertext` - The ciphertext and tag to authenticate and decrypt.
    /// * `aad` - Additional authenticated data.
    /// * `record` - Whether to record the message in the stream cipher transcript.
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<(), AeadError>;
}

#[derive(Debug, Clone)]
pub struct AeadLabels {
    key_full: FullLabels,
    key_active: ActiveLabels,
    iv_full: FullLabels,
    iv_active: ActiveLabels,
}

impl Into<StreamCipherLabels> for AeadLabels {
    fn into(self) -> StreamCipherLabels {
        StreamCipherLabels::new(self.key_full, self.key_active, self.iv_full, self.iv_active)
    }
}

impl Into<BlockCipherLabels> for AeadLabels {
    fn into(self) -> BlockCipherLabels {
        BlockCipherLabels::new(self.key_full, self.key_active)
    }
}

pub(crate) mod unchecked {
    #[derive(Debug, Clone)]
    pub struct UncheckedTagShare(pub Vec<u8>);
}
