//! This crate provides a 2PC block cipher implementation.
//!
//! Both parties work together to encrypt or share an encrypted block using a
//! shared key.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

mod cipher;
mod circuit;
mod config;
mod error;

use async_trait::async_trait;

use mpz_garble::value::ValueRef;

pub use crate::{
    cipher::MpcBlockCipher,
    circuit::{Aes128, BlockCipherCircuit},
};
pub use config::{BlockCipherConfig, BlockCipherConfigBuilder, BlockCipherConfigBuilderError};
pub use error::BlockCipherError;

/// Visibility of a message plaintext.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Visibility {
    /// Private message.
    Private,
    /// Blind message.
    Blind,
    /// Public message.
    Public,
}

/// A trait for MPC block ciphers.
#[async_trait]
pub trait BlockCipher<Cipher>: Send + Sync
where
    Cipher: BlockCipherCircuit,
{
    /// Sets the key for the block cipher.
    fn set_key(&mut self, key: ValueRef);

    /// Preprocesses `count` blocks.
    ///
    /// # Arguments
    ///
    /// * `visibility` - The visibility of the plaintext.
    /// * `count` - The number of blocks to preprocess.
    async fn preprocess(
        &mut self,
        visibility: Visibility,
        count: usize,
    ) -> Result<(), BlockCipherError>;

    /// Encrypts the given plaintext keeping it hidden from the other party(s).
    ///
    /// Returns the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to encrypt.
    async fn encrypt_private(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError>;

    /// Encrypts a plaintext provided by the other party(s).
    ///
    /// Returns the ciphertext.
    async fn encrypt_blind(&mut self) -> Result<Vec<u8>, BlockCipherError>;

    /// Encrypts a plaintext provided by both parties. Fails if the
    /// plaintext provided by both parties does not match.
    ///
    /// Returns an additive share of the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to encrypt.
    async fn encrypt_share(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_garble::{protocol::deap::mock::create_mock_deap_vm, Memory};

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
    #[ignore = "expensive"]
    async fn test_block_cipher_blind() {
        let leader_config = BlockCipherConfig::builder().id("test").build().unwrap();
        let follower_config = BlockCipherConfig::builder().id("test").build().unwrap();

        let key = [0u8; 16];

        let (leader_vm, follower_vm) = create_mock_deap_vm();

        // Key is public just for this test, typically it is private.
        let leader_key = leader_vm.new_public_input::<[u8; 16]>("key").unwrap();
        let follower_key = follower_vm.new_public_input::<[u8; 16]>("key").unwrap();

        leader_vm.assign(&leader_key, key).unwrap();
        follower_vm.assign(&follower_key, key).unwrap();

        let mut leader = MpcBlockCipher::<Aes128, _>::new(leader_config, leader_vm);
        leader.set_key(leader_key);

        let mut follower = MpcBlockCipher::<Aes128, _>::new(follower_config, follower_vm);
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
    #[ignore = "expensive"]
    async fn test_block_cipher_share() {
        let leader_config = BlockCipherConfig::builder().id("test").build().unwrap();
        let follower_config = BlockCipherConfig::builder().id("test").build().unwrap();

        let key = [0u8; 16];

        let (leader_vm, follower_vm) = create_mock_deap_vm();

        // Key is public just for this test, typically it is private.
        let leader_key = leader_vm.new_public_input::<[u8; 16]>("key").unwrap();
        let follower_key = follower_vm.new_public_input::<[u8; 16]>("key").unwrap();

        leader_vm.assign(&leader_key, key).unwrap();
        follower_vm.assign(&follower_key, key).unwrap();

        let mut leader = MpcBlockCipher::<Aes128, _>::new(leader_config, leader_vm);
        leader.set_key(leader_key);

        let mut follower = MpcBlockCipher::<Aes128, _>::new(follower_config, follower_vm);
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

    #[tokio::test]
    #[ignore = "expensive"]
    async fn test_block_cipher_preprocess() {
        let leader_config = BlockCipherConfig::builder().id("test").build().unwrap();
        let follower_config = BlockCipherConfig::builder().id("test").build().unwrap();

        let key = [0u8; 16];

        let (leader_vm, follower_vm) = create_mock_deap_vm();

        // Key is public just for this test, typically it is private.
        let leader_key = leader_vm.new_public_input::<[u8; 16]>("key").unwrap();
        let follower_key = follower_vm.new_public_input::<[u8; 16]>("key").unwrap();

        leader_vm.assign(&leader_key, key).unwrap();
        follower_vm.assign(&follower_key, key).unwrap();

        let mut leader = MpcBlockCipher::<Aes128, _>::new(leader_config, leader_vm);
        leader.set_key(leader_key);

        let mut follower = MpcBlockCipher::<Aes128, _>::new(follower_config, follower_vm);
        follower.set_key(follower_key);

        let plaintext = [0u8; 16];

        tokio::try_join!(
            leader.preprocess(Visibility::Private, 1),
            follower.preprocess(Visibility::Blind, 1)
        )
        .unwrap();

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt_private(plaintext.to_vec()),
            follower.encrypt_blind()
        )
        .unwrap();

        let expected = aes128(key, plaintext);

        assert_eq!(leader_ciphertext, expected.to_vec());
        assert_eq!(leader_ciphertext, follower_ciphertext);

        tokio::try_join!(
            leader.preprocess(Visibility::Public, 1),
            follower.preprocess(Visibility::Public, 1)
        )
        .unwrap();

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
