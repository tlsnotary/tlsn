//! This module provides an implementation of 2PC AES-GCM which implements the `AEADLeader` and `AEADFollower`
//! traits in this crate.

mod config;
mod follower;
mod leader;

use std::ops::Add;

pub use config::{
    AesGcmFollowerConfig, AesGcmFollowerConfigBuilder, AesGcmFollowerConfigBuilderError,
    AesGcmLeaderConfig, AesGcmLeaderConfigBuilder, AesGcmLeaderConfigBuilderError,
};
pub use follower::AesGcmFollower;
pub use leader::AesGcmLeader;

use crate::AeadError;

pub const AES_GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct AesGcmTagShare(pub(crate) [u8; 16]);

impl AesGcmTagShare {
    pub fn from_unchecked(share: crate::unchecked::UncheckedTagShare) -> Result<Self, AeadError> {
        if share.0.len() != 16 {
            return Err(AeadError::ValidationError(
                "Received tag share is not 16 bytes long".to_string(),
            ));
        }
        let mut result = [0u8; 16];
        result.copy_from_slice(&share.0);
        Ok(Self(result))
    }
}

impl AsRef<[u8]> for AesGcmTagShare {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Add for AesGcmTagShare {
    type Output = Vec<u8>;

    fn add(self, rhs: Self) -> Self::Output {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }
}

#[cfg(feature = "mock")]
pub mod mock {
    use crate::AeadLabels;

    use super::*;

    use futures::lock::Mutex;
    use mpc_circuits::BitOrder;
    use std::sync::Arc;

    use block_cipher::{
        mock::{create_mock_block_cipher_pair, MockDEBlockCipherFollower, MockDEBlockCipherLeader},
        Aes128, BlockCipher, BlockCipherConfigBuilder, Role as BlockCipherRole,
    };
    use mpc_core::garble::{ChaChaEncoder, Encoder, FullLabels};
    use share_conversion_aio::conversion::recorder::Void;
    use tlsn_stream_cipher::{
        cipher::Aes128Ctr,
        mock::{create_mock_stream_cipher_pair, MockStreamCipherFollower, MockStreamCipherLeader},
        StreamCipherConfigBuilder, StreamCipherFollower, StreamCipherLeader,
    };
    use tlsn_universal_hash::ghash::{mock_ghash_pair, MockGhashReceiver, MockGhashSender};
    use utils_aio::duplex::DuplexChannel;

    pub type MockAesGcmLeader = AesGcmLeader<
        MockDEBlockCipherLeader<Aes128>,
        MockStreamCipherLeader<Aes128Ctr>,
        MockGhashSender<Void, Void>,
    >;

    pub type MockAesGcmFollower = AesGcmFollower<
        MockDEBlockCipherFollower<Aes128>,
        MockStreamCipherFollower<Aes128Ctr>,
        MockGhashReceiver<Void, Void>,
    >;

    pub fn create_mock_aes_gcm_pair(
        leader_config: AesGcmLeaderConfig,
        leader_encoder: Arc<Mutex<ChaChaEncoder>>,
        follower_config: AesGcmFollowerConfig,
        follower_encoder: Arc<Mutex<ChaChaEncoder>>,
    ) -> (MockAesGcmLeader, MockAesGcmFollower) {
        let (leader_channel, follower_channel) = DuplexChannel::new();

        let (mut block_cipher_leader, mut block_cipher_follower) =
            create_mock_block_cipher_pair::<Aes128>(
                BlockCipherConfigBuilder::default()
                    .id("mock-block-cipher".to_string())
                    .role(BlockCipherRole::Leader)
                    .build()
                    .unwrap(),
                BlockCipherConfigBuilder::default()
                    .id("mock-block-cipher".to_string())
                    .role(BlockCipherRole::Follower)
                    .build()
                    .unwrap(),
            );

        block_cipher_leader.set_encoder(leader_encoder.clone());
        block_cipher_follower.set_encoder(follower_encoder.clone());

        let (mut stream_cipher_leader, mut stream_cipher_follower) = create_mock_stream_cipher_pair(
            StreamCipherConfigBuilder::default()
                .id("mock-stream-cipher".to_string())
                .start_ctr(2)
                .build()
                .unwrap(),
            StreamCipherConfigBuilder::default()
                .id("mock-stream-cipher".to_string())
                .start_ctr(2)
                .build()
                .unwrap(),
        );

        stream_cipher_leader.set_encoder(leader_encoder.clone());
        stream_cipher_follower.set_encoder(follower_encoder.clone());

        let (universal_hash_sender, universal_hash_receiver) = mock_ghash_pair(1024);

        let leader = AesGcmLeader::new(
            leader_config,
            Box::new(leader_channel),
            block_cipher_leader,
            stream_cipher_leader,
            universal_hash_sender,
        );

        let follower = AesGcmFollower::new(
            follower_config,
            Box::new(follower_channel),
            block_cipher_follower,
            stream_cipher_follower,
            universal_hash_receiver,
        );

        (leader, follower)
    }

    pub fn create_mock_aead_labels(
        key: Vec<u8>,
        iv: Vec<u8>,
    ) -> ((ChaChaEncoder, AeadLabels), (ChaChaEncoder, AeadLabels)) {
        let mut leader_encoder = ChaChaEncoder::new([0; 32], BitOrder::Msb0);
        let mut follower_encoder = ChaChaEncoder::new([1; 32], BitOrder::Msb0);

        let leader_delta = leader_encoder.get_delta();
        let leader_key_full_labels =
            FullLabels::generate(leader_encoder.get_stream(0), 128, Some(leader_delta));
        let leader_iv_full_labels =
            FullLabels::generate(leader_encoder.get_stream(0), 32, Some(leader_delta));

        let follower_delta = follower_encoder.get_delta();
        let follower_key_full_labels =
            FullLabels::generate(follower_encoder.get_stream(0), 128, Some(follower_delta));
        let follower_iv_full_labels =
            FullLabels::generate(follower_encoder.get_stream(0), 32, Some(follower_delta));

        let leader_labels = AeadLabels {
            key_full: leader_key_full_labels.clone(),
            key_active: follower_key_full_labels
                .select(&key.clone().into(), BitOrder::Msb0)
                .unwrap(),
            iv_full: leader_iv_full_labels.clone(),
            iv_active: follower_iv_full_labels
                .select(&iv.clone().into(), BitOrder::Msb0)
                .unwrap(),
        };

        let follower_labels = AeadLabels {
            key_full: follower_key_full_labels.clone(),
            key_active: leader_key_full_labels
                .select(&key.clone().into(), BitOrder::Msb0)
                .unwrap(),
            iv_full: follower_iv_full_labels.clone(),
            iv_active: leader_iv_full_labels
                .select(&iv.clone().into(), BitOrder::Msb0)
                .unwrap(),
        };

        (
            (leader_encoder, leader_labels),
            (follower_encoder, follower_labels),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{AeadFollower, AeadLeader};

    use super::*;
    use mock::*;

    use futures::lock::Mutex;
    use std::sync::Arc;

    use ::aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes128Gcm, Nonce,
    };

    fn reference_impl(
        key: &[u8],
        iv: &[u8],
        explicit_nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(key).unwrap();
        let nonce = [iv, explicit_nonce].concat();
        let nonce = Nonce::from_slice(nonce.as_slice());

        let mut ciphertext = plaintext.to_vec();
        cipher
            .encrypt_in_place(nonce, aad, &mut ciphertext)
            .unwrap();

        ciphertext
    }

    async fn setup_pair(key: Vec<u8>, iv: Vec<u8>) -> (MockAesGcmLeader, MockAesGcmFollower) {
        let leader_config = AesGcmLeaderConfigBuilder::default().build().unwrap();
        let follower_config = AesGcmFollowerConfigBuilder::default().build().unwrap();

        let ((leader_encoder, leader_labels), (follower_encoder, follower_labels)) =
            create_mock_aead_labels(key, iv);

        let (mut leader, mut follower) = create_mock_aes_gcm_pair(
            leader_config,
            Arc::new(Mutex::new(leader_encoder)),
            follower_config,
            Arc::new(Mutex::new(follower_encoder)),
        );

        tokio::try_join!(
            leader.set_keys(leader_labels),
            follower.set_keys(follower_labels)
        )
        .unwrap();

        (leader, follower)
    }

    #[tokio::test]
    async fn test_aes_gcm_encrypt_private() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt_private(
                explicit_nonce.clone(),
                plaintext.clone(),
                aad.clone(),
                false
            ),
            follower.encrypt_blind(explicit_nonce.clone(), plaintext.len(), aad.clone(), false)
        )
        .unwrap();

        assert_eq!(leader_ciphertext, follower_ciphertext);
        assert_eq!(
            leader_ciphertext,
            reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad)
        );
    }

    #[tokio::test]
    async fn test_aes_gcm_encrypt_public() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt(
                explicit_nonce.clone(),
                plaintext.clone(),
                aad.clone(),
                false
            ),
            follower.encrypt(
                explicit_nonce.clone(),
                plaintext.clone(),
                aad.clone(),
                false
            )
        )
        .unwrap();

        assert_eq!(leader_ciphertext, follower_ciphertext);
        assert_eq!(
            leader_ciphertext,
            reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad)
        );
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_private() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, _) = tokio::try_join!(
            leader.decrypt_private(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt_blind(explicit_nonce.clone(), ciphertext, aad.clone(), false)
        )
        .unwrap();

        assert_eq!(leader_plaintext, plaintext);
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_private_bad_tag() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let len = ciphertext.len();

        // corrupt tag
        let mut corrupted = ciphertext.clone();
        corrupted[len - 1] = corrupted[len - 1] - 1;

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // leader receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(
                explicit_nonce.clone(),
                corrupted.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt_blind(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            )
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));

        // follower receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt_blind(
                explicit_nonce.clone(),
                corrupted.clone(),
                aad.clone(),
                false
            )
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_public() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, follower_plaintext) = tokio::try_join!(
            leader.decrypt(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt(explicit_nonce.clone(), ciphertext, aad.clone(), false)
        )
        .unwrap();

        assert_eq!(leader_plaintext, plaintext);
        assert_eq!(leader_plaintext, follower_plaintext);
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_public_bad_tag() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let len = ciphertext.len();

        // corrupt tag
        let mut corrupted = ciphertext.clone();
        corrupted[len - 1] = corrupted[len - 1] - 1;

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // leader receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt(
                explicit_nonce.clone(),
                corrupted.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            )
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));

        // follower receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt(
                explicit_nonce.clone(),
                corrupted.clone(),
                aad.clone(),
                false
            )
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));
    }
}
