//! This module provides an implementation of 2PC AES-GCM which implements the `AEADLeader` and `AEADFollower`
//! traits in this crate.

mod config;
mod follower;
mod leader;
#[cfg(feature = "mock")]
pub mod mock;

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
        let leader_config = AesGcmLeaderConfigBuilder::default()
            .id("test".to_string())
            .build()
            .unwrap();
        let follower_config = AesGcmFollowerConfigBuilder::default()
            .id("test".to_string())
            .build()
            .unwrap();

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
            leader.encrypt_public(
                explicit_nonce.clone(),
                plaintext.clone(),
                aad.clone(),
                false
            ),
            follower.encrypt_public(
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
            leader.decrypt_public(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt_public(explicit_nonce.clone(), ciphertext, aad.clone(), false)
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
            leader.decrypt_public(
                explicit_nonce.clone(),
                corrupted.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt_public(
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
            leader.decrypt_public(
                explicit_nonce.clone(),
                ciphertext.clone(),
                aad.clone(),
                false
            ),
            follower.decrypt_public(
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
