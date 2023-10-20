//! This crate provides implementations of 2PC AEADs for authenticated encryption with
//! a shared key.
//!
//! Both parties can work together to encrypt and decrypt messages with different visibility
//! configurations. See [`Aead`] for more information on the interface.
//!
//! For example, one party can privately provide the plaintext to encrypt, while both parties
//! can see the ciphertext and the tag. Or, both parties can cooperate to decrypt a ciphertext
//! and verify the tag, while only one party can see the plaintext.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod aes_gcm;
pub mod msg;

pub use msg::AeadMessage;

use async_trait::async_trait;

use mpz_garble::value::ValueRef;
use utils_aio::duplex::Duplex;

/// A channel for sending and receiving AEAD messages.
pub type AeadChannel = Box<dyn Duplex<AeadMessage>>;

/// An error that can occur during AEAD operations.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum AeadError {
    #[error(transparent)]
    BlockCipherError(#[from] block_cipher::BlockCipherError),
    #[error(transparent)]
    StreamCipherError(#[from] tlsn_stream_cipher::StreamCipherError),
    #[error(transparent)]
    UniversalHashError(#[from] tlsn_universal_hash::UniversalHashError),
    #[error("Corrupted Tag")]
    CorruptedTag,
    #[error("Validation Error: {0}")]
    ValidationError(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// This trait defines the interface for AEADs.
#[async_trait]
pub trait Aead: Send {
    /// Sets the key for the AEAD.
    async fn set_key(&mut self, key: ValueRef, iv: ValueRef) -> Result<(), AeadError>;

    /// Sets the transcript id
    ///
    /// The AEAD assigns unique identifiers to each byte of plaintext
    /// during encryption and decryption.
    ///
    /// For example, if the transcript id is set to `foo`, then the first byte will
    /// be assigned the id `foo/0`, the second byte `foo/1`, and so on.
    ///
    /// Each transcript id has an independent counter.
    ///
    /// # Note
    ///
    /// The state of a transcript counter is preserved between calls to `set_transcript_id`.
    fn set_transcript_id(&mut self, id: &str);

    /// Encrypts a plaintext message, returning the ciphertext and tag.
    ///
    /// The plaintext is provided by both parties.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for encryption.
    /// * `plaintext` - The plaintext to encrypt.
    /// * `aad` - Additional authenticated data.
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError>;

    /// Encrypts a plaintext message, hiding it from the other party, returning the ciphertext and tag.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for encryption.
    /// * `plaintext` - The plaintext to encrypt.
    /// * `aad` - Additional authenticated data.
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError>;

    /// Encrypts a plaintext message provided by the other party, returning
    /// the ciphertext and tag.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for encryption.
    /// * `plaintext_len` - The length of the plaintext to encrypt.
    /// * `aad` - Additional authenticated data.
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext_len: usize,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypts a ciphertext message, returning the plaintext to both parties.
    ///
    /// This method checks the authenticity of the ciphertext, tag and additional data.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for decryption.
    /// * `ciphertext` - The ciphertext and tag to authenticate and decrypt.
    /// * `aad` - Additional authenticated data.
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypts a ciphertext message, returning the plaintext only to this party.
    ///
    /// This method checks the authenticity of the ciphertext, tag and additional data.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for decryption.
    /// * `ciphertext` - The ciphertext and tag to authenticate and decrypt.
    /// * `aad` - Additional authenticated data.
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypts a ciphertext message, returning the plaintext only to the other party.
    ///
    /// This method checks the authenticity of the ciphertext, tag and additional data.
    ///
    /// * `explicit_nonce` - The explicit nonce to use for decryption.
    /// * `ciphertext` - The ciphertext and tag to authenticate and decrypt.
    /// * `aad` - Additional authenticated data.
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AeadError>;
}
