//! This crate provides a 2PC block cipher implementation.
//!
//! Both parties work together to encrypt or share an encrypted block using a shared key.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

mod cipher;
mod circuit;
mod config;

use async_trait::async_trait;

use mpz_garble::value::ValueRef;

pub use crate::{
    cipher::MpcBlockCipher,
    circuit::{Aes128, BlockCipherCircuit},
};
pub use config::{BlockCipherConfig, BlockCipherConfigBuilder, BlockCipherConfigBuilderError};

/// Errors that can occur when using the block cipher
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum BlockCipherError {
    #[error(transparent)]
    MemoryError(#[from] mpz_garble::MemoryError),
    #[error(transparent)]
    ExecutionError(#[from] mpz_garble::ExecutionError),
    #[error(transparent)]
    DecodeError(#[from] mpz_garble::DecodeError),
    #[error("Cipher key not set")]
    KeyNotSet,
    #[error("Input does not match block length: expected {0}, got {1}")]
    InvalidInputLength(usize, usize),
}

/// A trait for MPC block ciphers
#[async_trait]
pub trait BlockCipher<Cipher>: Send + Sync
where
    Cipher: BlockCipherCircuit,
{
    /// Sets the key for the block cipher.
    fn set_key(&mut self, key: ValueRef);

    /// Encrypts the given plaintext keeping it hidden from the other party(s).
    ///
    /// Returns the ciphertext
    ///
    /// * `plaintext` - The plaintext to encrypt
    async fn encrypt_private(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError>;

    /// Encrypts a plaintext provided by the other party(s).
    ///
    /// Returns the ciphertext
    async fn encrypt_blind(&mut self) -> Result<Vec<u8>, BlockCipherError>;

    /// Encrypts a plaintext provided by both parties. Fails if the
    /// plaintext provided by both parties does not match.
    ///
    /// Returns an additive share of the ciphertext
    ///
    /// * `plaintext` - The plaintext to encrypt
    async fn encrypt_share(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_garble::{protocol::deap::mock::create_mock_deap_vm, Memory, Vm};

    use crate::circuit::Aes128;

    use ::aes::Aes128 as TestAes128;
    use ::cipher::{BlockEncrypt, KeyInit};

    fn aes128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
        let mut msg = msg.into();
        let cipher = TestAes128::new(&key.into());
        cipher.encrypt_block(&mut msg);
        msg.into()
    }

    #[tokio::test]
    async fn test_block_cipher_blind() {
        let leader_config = BlockCipherConfig::builder().id("test").build().unwrap();
        let follower_config = BlockCipherConfig::builder().id("test").build().unwrap();

        let key = [0u8; 16];

        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test").await;
        let leader_thread = leader_vm.new_thread("test").await.unwrap();
        let follower_thread = follower_vm.new_thread("test").await.unwrap();

        // Key is public just for this test, typically it is private
        let leader_key = leader_thread.new_public_input::<[u8; 16]>("key").unwrap();
        let follower_key = follower_thread.new_public_input::<[u8; 16]>("key").unwrap();

        leader_thread.assign(&leader_key, key).unwrap();
        follower_thread.assign(&follower_key, key).unwrap();

        let mut leader = MpcBlockCipher::<Aes128, _>::new(leader_config, leader_thread);
        leader.set_key(leader_key);

        let mut follower = MpcBlockCipher::<Aes128, _>::new(follower_config, follower_thread);
        follower.set_key(follower_key);

        let plaintext = [0u8; 16];

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt_private(plaintext.to_vec()),
            follower.encrypt_blind()
        )
        .unwrap();

        let expected = aes128(key, plaintext);

        assert_eq!(leader_ciphertext, expected.to_vec());
        assert_eq!(leader_ciphertext, follower_ciphertext);
    }

    #[tokio::test]
    async fn test_block_cipher_share() {
        let leader_config = BlockCipherConfig::builder().id("test").build().unwrap();
        let follower_config = BlockCipherConfig::builder().id("test").build().unwrap();

        let key = [0u8; 16];

        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test").await;
        let leader_thread = leader_vm.new_thread("test").await.unwrap();
        let follower_thread = follower_vm.new_thread("test").await.unwrap();

        // Key is public just for this test, typically it is private
        let leader_key = leader_thread.new_public_input::<[u8; 16]>("key").unwrap();
        let follower_key = follower_thread.new_public_input::<[u8; 16]>("key").unwrap();

        leader_thread.assign(&leader_key, key).unwrap();
        follower_thread.assign(&follower_key, key).unwrap();

        let mut leader = MpcBlockCipher::<Aes128, _>::new(leader_config, leader_thread);
        leader.set_key(leader_key);

        let mut follower = MpcBlockCipher::<Aes128, _>::new(follower_config, follower_thread);
        follower.set_key(follower_key);

        let plaintext = [0u8; 16];

        let (leader_share, follower_share) = tokio::try_join!(
            leader.encrypt_share(plaintext.to_vec()),
            follower.encrypt_share(plaintext.to_vec())
        )
        .unwrap();

        let expected = aes128(key, plaintext);

        let result: [u8; 16] = std::array::from_fn(|i| leader_share[i] ^ follower_share[i]);

        assert_eq!(result, expected);
    }
}
