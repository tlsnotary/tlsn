//! This crate provides a 2PC block cipher implementation.
//!
//! Both parties work together to encrypt or share an encrypted block using a shared key.

mod cipher;
mod config;
mod suite;

use std::sync::Arc;

use async_trait::async_trait;
use futures::lock::Mutex;

use mpc_aio::protocol::garble::GCError;
use mpc_core::garble::{ActiveLabels, ChaChaEncoder, FullLabels};

pub use crate::{
    cipher::DEBlockCipher,
    suite::{
        Aes128, Aes128Circuit, Aes128ShareCircuit, BlockCipherCircuit, BlockCipherCircuitSuite,
        BlockCipherShareCircuit,
    },
};
pub use config::{
    BlockCipherConfig, BlockCipherConfigBuilder, BlockCipherConfigBuilderError, Role,
};

#[derive(Debug, thiserror::Error)]
pub enum BlockCipherError {
    #[error("MuxerError: {0}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error("GCFactoryError: {0}")]
    GCFactoryError(#[from] mpc_aio::protocol::garble::factory::GCFactoryError),
    #[error("GCError: {0}")]
    GCError(#[from] GCError),
    #[error("Cipher key labels not set")]
    KeysNotSet,
    #[error("Encoder not set")]
    EncoderNotSet,
    #[error("Input does not match block length: expected {0}, got {1}")]
    InvalidInputLength(usize, usize),
}

#[derive(Clone)]
pub struct BlockCipherLabels {
    pub key_full: FullLabels,
    pub key_active: ActiveLabels,
}

impl BlockCipherLabels {
    /// Creates a new set of block cipher labels.
    pub fn new(key_full: FullLabels, key_active: ActiveLabels) -> Self {
        Self {
            key_full,
            key_active,
        }
    }

    /// Returns the full labels for the key input
    pub fn key_full(&self) -> &FullLabels {
        &self.key_full
    }

    /// Returns the active labels for the key input
    pub fn key_active(&self) -> &ActiveLabels {
        &self.key_active
    }
}

#[async_trait]
pub trait BlockCipher<Cipher>
where
    Cipher: BlockCipherCircuitSuite,
    Self: Sized + Send,
{
    /// Sets the key input labels for the block cipher.
    ///
    /// * `labels`: The labels to use for the key input.
    fn set_keys(&mut self, labels: BlockCipherLabels);

    /// Sets the encoder used to generate the input labels
    /// used during 2PC.
    ///
    /// * `encoder`: The encoder to use
    fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>);

    /// Encrypts the given plaintext.
    ///
    /// Returns the ciphertext
    ///
    /// * `plaintext` - The plaintext to encrypt
    async fn encrypt_private(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError>;

    /// Encrypts a plaintext provided by the other party
    ///
    /// Returns the ciphertext
    async fn encrypt_blind(&mut self) -> Result<Vec<u8>, BlockCipherError>;

    /// Encrypts a plaintext provided by both parties. Fails if the
    /// plaintext provided by both parties does not match.
    ///
    /// Returns the additive share of the ciphertext
    ///
    /// * `plaintext` - The plaintext to encrypt
    /// * `mask` - The additive share of the mask to use
    async fn encrypt_share(
        &mut self,
        plaintext: Vec<u8>,
        mask: Vec<u8>,
    ) -> Result<Vec<u8>, BlockCipherError>;
}

#[cfg(feature = "mock")]
pub mod mock {
    use mpc_aio::protocol::garble::{
        exec::dual::mock::{MockDualExFollower, MockDualExLeader},
        factory::dual::mock::{create_mock_dualex_factory, MockDualExFactory},
    };
    use mpc_circuits::{BitOrder, Value};
    use mpc_core::garble::Encoder;

    use super::*;

    pub type MockDEBlockCipherLeader<C> = DEBlockCipher<C, MockDualExFactory, MockDualExLeader>;
    pub type MockDEBlockCipherFollower<C> = DEBlockCipher<C, MockDualExFactory, MockDualExFollower>;

    pub fn create_labels<C: BlockCipherCircuitSuite>(
        key: Vec<u8>,
        leader_encoder: &mut ChaChaEncoder,
        follower_encoder: &mut ChaChaEncoder,
    ) -> (BlockCipherLabels, BlockCipherLabels) {
        let cipher = C::BlockCipherCircuit::default();

        let leader_key_full = leader_encoder.encode(0, &cipher.key());
        let follower_key_full = follower_encoder.encode(0, &cipher.key());

        let leader_key_active = follower_key_full
            .select(&Value::Bytes(key.clone()), BitOrder::Msb0)
            .unwrap();
        let follower_key_active = leader_key_full
            .select(&Value::Bytes(key), BitOrder::Msb0)
            .unwrap();

        let leader_labels = BlockCipherLabels {
            key_full: leader_key_full,
            key_active: leader_key_active,
        };

        let follower_labels = BlockCipherLabels {
            key_full: follower_key_full,
            key_active: follower_key_active,
        };

        (leader_labels, follower_labels)
    }

    pub fn create_mock_block_cipher_pair<C: BlockCipherCircuitSuite>(
        leader_config: BlockCipherConfig,
        follower_config: BlockCipherConfig,
    ) -> (MockDEBlockCipherLeader<C>, MockDEBlockCipherFollower<C>) {
        let de_factory = create_mock_dualex_factory();

        let leader = DEBlockCipher::new(leader_config, de_factory.clone());

        let follower = DEBlockCipher::new(follower_config, de_factory);

        (leader, follower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mock::*;
    use mpc_circuits::BitOrder;

    use crate::{config::Role, suite::Aes128};

    use ::aes::Aes128 as TestAes128;
    use ::cipher::{BlockEncrypt, KeyInit};

    fn setup_pair<C: BlockCipherCircuitSuite>(
        key: Vec<u8>,
        leader_config: BlockCipherConfig,
        follower_config: BlockCipherConfig,
    ) -> (MockDEBlockCipherLeader<C>, MockDEBlockCipherFollower<C>) {
        let (mut leader, mut follower) =
            create_mock_block_cipher_pair::<C>(leader_config, follower_config);

        let mut leader_encoder = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);
        let mut follower_encoder = ChaChaEncoder::new([1u8; 32], BitOrder::Msb0);

        let (leader_labels, follower_labels) =
            create_labels::<Aes128>(key, &mut leader_encoder, &mut follower_encoder);

        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        leader.set_keys(leader_labels);
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));
        follower.set_keys(follower_labels);

        (leader, follower)
    }

    #[tokio::test]
    async fn test_block_cipher_blind() {
        let leader_config = BlockCipherConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Leader)
            .build()
            .unwrap();

        let follower_config = BlockCipherConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Follower)
            .build()
            .unwrap();

        let key = [0u8; 16];

        let (mut leader, mut follower) =
            setup_pair::<Aes128>(key.to_vec(), leader_config, follower_config);

        let plaintext = [0u8; 16];

        let (leader_result, follower_result) = tokio::join!(
            leader.encrypt_private(plaintext.to_vec()),
            follower.encrypt_blind()
        );

        let leader_ciphertext = leader_result.unwrap();
        let follower_ciphertext = follower_result.unwrap();

        let mut reference_ciphertext = plaintext.into();
        let cipher = TestAes128::new(&key.into());
        cipher.encrypt_block(&mut reference_ciphertext);

        assert_eq!(leader_ciphertext, reference_ciphertext.to_vec());
        assert_eq!(leader_ciphertext, follower_ciphertext);
    }

    #[tokio::test]
    async fn test_block_cipher_share() {
        let leader_config = BlockCipherConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Leader)
            .build()
            .unwrap();

        let follower_config = BlockCipherConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Follower)
            .build()
            .unwrap();

        let key = [0u8; 16];

        let (mut leader, mut follower) =
            setup_pair::<Aes128>(key.to_vec(), leader_config, follower_config);

        let plaintext = [0u8; 16];
        let leader_mask = vec![1u8; 16];
        let follower_mask = vec![2u8; 16];

        let (leader_result, follower_result) = tokio::join!(
            leader.encrypt_share(plaintext.to_vec(), leader_mask.clone()),
            follower.encrypt_share(plaintext.to_vec(), follower_mask.clone())
        );

        let leader_share = leader_result.unwrap();
        let follower_share = follower_result.unwrap();

        let mut reference_ciphertext = plaintext.into();
        let cipher = TestAes128::new(&key.into());
        cipher.encrypt_block(&mut reference_ciphertext);

        let ciphertext = leader_share
            .iter()
            .zip(follower_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();

        assert_eq!(ciphertext, reference_ciphertext.to_vec());
    }

    #[tokio::test]
    async fn test_block_cipher_share_unequal_plaintext() {
        let leader_config = BlockCipherConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Leader)
            .build()
            .unwrap();

        let follower_config = BlockCipherConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Follower)
            .build()
            .unwrap();

        let key = [0u8; 16];

        let (mut leader, mut follower) =
            setup_pair::<Aes128>(key.to_vec(), leader_config, follower_config);

        let plaintext = [0u8; 16];
        let plaintext_1 = [1u8; 16];
        let leader_mask = vec![1u8; 16];
        let follower_mask = vec![2u8; 16];

        let (leader_result, follower_result) = tokio::join!(
            leader.encrypt_share(plaintext.to_vec(), leader_mask.clone()),
            follower.encrypt_share(plaintext_1.to_vec(), follower_mask.clone())
        );

        assert!(leader_result.is_err());
        assert!(follower_result.is_err());
    }
}
