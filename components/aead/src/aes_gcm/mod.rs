//! This module provides an implementation of 2PC AES-GCM.

mod config;
#[cfg(feature = "mock")]
pub mod mock;
mod tag;

pub use config::{AesGcmConfig, AesGcmConfigBuilder, AesGcmConfigBuilderError, Role};

use crate::{
    msg::{AeadMessage, TagShare},
    Aead, AeadChannel, AeadError,
};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt, TryFutureExt};

use block_cipher::{Aes128, BlockCipher};
use mpz_core::commit::HashCommit;
use mpz_garble::value::ValueRef;
use tlsn_stream_cipher::{Aes128Ctr, StreamCipher};
use tlsn_universal_hash::UniversalHash;
use utils_aio::expect_msg_or_err;

pub(crate) use tag::AesGcmTagShare;
use tag::{build_ghash_data, AES_GCM_TAG_LEN};

/// An implementation of 2PC AES-GCM.
pub struct MpcAesGcm {
    config: AesGcmConfig,
    channel: AeadChannel,
    aes_block: Box<dyn BlockCipher<Aes128>>,
    aes_ctr: Box<dyn StreamCipher<Aes128Ctr>>,
    ghash: Box<dyn UniversalHash>,
}

impl std::fmt::Debug for MpcAesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAesGcm")
            .field("config", &self.config)
            .field("channel", &"AeadChannel {{ ... }}")
            .field("aes_block", &"BlockCipher {{ ... }}")
            .field("aes_ctr", &"StreamCipher {{ ... }}")
            .field("ghash", &"UniversalHash {{ ... }}")
            .finish()
    }
}

impl MpcAesGcm {
    /// Creates a new instance of [`MpcAesGcm`].
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(channel, aes_block, aes_ctr, ghash), ret)
    )]
    pub fn new(
        config: AesGcmConfig,
        channel: AeadChannel,
        aes_block: Box<dyn BlockCipher<Aes128>>,
        aes_ctr: Box<dyn StreamCipher<Aes128Ctr>>,
        ghash: Box<dyn UniversalHash>,
    ) -> Self {
        Self {
            config,
            channel,
            aes_block,
            aes_ctr,
            ghash,
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err))]
    async fn compute_j0_share(&mut self, explicit_nonce: Vec<u8>) -> Result<Vec<u8>, AeadError> {
        let j0_share = self
            .aes_ctr
            .share_keystream_block(explicit_nonce.clone(), 1)
            .await?;

        Ok(j0_share)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn compute_tag_share(
        &mut self,
        explicit_nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<AesGcmTagShare, AeadError> {
        let j0_share = self.compute_j0_share(explicit_nonce.clone()).await?;

        let hash = self
            .ghash
            .finalize(build_ghash_data(aad, ciphertext))
            .await?;

        let mut tag_share = [0u8; 16];
        tag_share.copy_from_slice(&hash[..]);
        for i in 0..16 {
            tag_share[i] ^= j0_share[i];
        }

        Ok(AesGcmTagShare(tag_share))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn compute_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let tag_share = self
            .compute_tag_share(explicit_nonce, aad, ciphertext.clone())
            .await?;

        let tag = match self.config.role() {
            Role::Leader => {
                // Send commitment of tag share to follower
                let (tag_share_decommitment, tag_share_commitment) =
                    TagShare::from(tag_share).hash_commit();

                self.channel
                    .send(AeadMessage::TagShareCommitment(tag_share_commitment))
                    .await?;

                // Expect tag share from follower
                let msg = expect_msg_or_err!(self.channel, AeadMessage::TagShare)?;

                let other_tag_share = AesGcmTagShare::from_unchecked(&msg.share)?;

                // Send decommitment (tag share) to follower
                self.channel
                    .send(AeadMessage::TagShareDecommitment(tag_share_decommitment))
                    .await?;

                tag_share + other_tag_share
            }
            Role::Follower => {
                // Wait for commitment from leader
                let commitment = expect_msg_or_err!(self.channel, AeadMessage::TagShareCommitment)?;

                // Send tag share to leader
                self.channel
                    .send(AeadMessage::TagShare(tag_share.into()))
                    .await?;

                // Expect decommitment (tag share) from leader
                let decommitment =
                    expect_msg_or_err!(self.channel, AeadMessage::TagShareDecommitment)?;

                // Verify decommitment
                decommitment.verify(&commitment).map_err(|_| {
                    AeadError::ValidationError(
                        "Leader tag share commitment verification failed".to_string(),
                    )
                })?;

                let other_tag_share =
                    AesGcmTagShare::from_unchecked(&decommitment.into_inner().share)?;

                tag_share + other_tag_share
            }
        };

        Ok(tag)
    }
}

#[async_trait]
impl Aead for MpcAesGcm {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", err))]
    async fn set_key(&mut self, key: ValueRef, iv: ValueRef) -> Result<(), AeadError> {
        self.aes_block.set_key(key.clone());
        self.aes_ctr.set_key(key, iv);

        // Share zero block
        let h_share = self.aes_block.encrypt_share(vec![0u8; 16]).await?;

        self.ghash.set_key(h_share).await?;

        Ok(())
    }

    fn set_transcript_id(&mut self, id: &str) {
        self.aes_ctr.set_transcript_id(id)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_public(explicit_nonce.clone(), plaintext)
            .await?;

        let tag = self
            .compute_tag(explicit_nonce, ciphertext.clone(), aad)
            .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_private(explicit_nonce.clone(), plaintext)
            .await?;

        let tag = self
            .compute_tag(explicit_nonce, ciphertext.clone(), aad)
            .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext_len: usize,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_blind(explicit_nonce.clone(), plaintext_len)
            .await?;

        let tag = self
            .compute_tag(explicit_nonce, ciphertext.clone(), aad)
            .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let purported_tag = ciphertext.split_off(ciphertext.len() - AES_GCM_TAG_LEN);

        let tag = self
            .compute_tag(explicit_nonce.clone(), ciphertext.clone(), aad)
            .await?;

        // Reject if tag is incorrect
        if tag != purported_tag {
            return Err(AeadError::CorruptedTag);
        }

        self.aes_ctr
            .decrypt_public(explicit_nonce, ciphertext)
            .map_err(AeadError::from)
            .await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let purported_tag = ciphertext.split_off(ciphertext.len() - AES_GCM_TAG_LEN);

        let tag = self
            .compute_tag(explicit_nonce.clone(), ciphertext.clone(), aad)
            .await?;

        // Reject if tag is incorrect
        if tag != purported_tag {
            return Err(AeadError::CorruptedTag);
        }

        self.aes_ctr
            .decrypt_private(explicit_nonce, ciphertext)
            .map_err(AeadError::from)
            .await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AeadError> {
        let purported_tag = ciphertext.split_off(ciphertext.len() - AES_GCM_TAG_LEN);

        let tag = self
            .compute_tag(explicit_nonce.clone(), ciphertext.clone(), aad)
            .await?;

        // Reject if tag is incorrect
        if tag != purported_tag {
            return Err(AeadError::CorruptedTag);
        }

        self.aes_ctr
            .decrypt_blind(explicit_nonce, ciphertext)
            .map_err(AeadError::from)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{mock::create_mock_aes_gcm_pair, *};
    use crate::Aead;

    use mpz_garble::{
        protocol::deap::mock::{create_mock_deap_vm, MockFollower, MockLeader},
        Memory, Vm,
    };

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

    async fn setup_pair(
        key: Vec<u8>,
        iv: Vec<u8>,
    ) -> ((MpcAesGcm, MpcAesGcm), (MockLeader, MockFollower)) {
        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test_vm").await;

        let leader_thread = leader_vm.new_thread("test_thread").await.unwrap();
        let leader_key = leader_thread
            .new_public_array_input::<u8>("key", key.len())
            .unwrap();
        let leader_iv = leader_thread
            .new_public_array_input::<u8>("iv", iv.len())
            .unwrap();

        leader_thread.assign(&leader_key, key.clone()).unwrap();
        leader_thread.assign(&leader_iv, iv.clone()).unwrap();

        let follower_thread = follower_vm.new_thread("test_thread").await.unwrap();
        let follower_key = follower_thread
            .new_public_array_input::<u8>("key", key.len())
            .unwrap();
        let follower_iv = follower_thread
            .new_public_array_input::<u8>("iv", iv.len())
            .unwrap();

        follower_thread.assign(&follower_key, key.clone()).unwrap();
        follower_thread.assign(&follower_iv, iv.clone()).unwrap();

        let leader_config = AesGcmConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Leader)
            .build()
            .unwrap();
        let follower_config = AesGcmConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Follower)
            .build()
            .unwrap();

        let (mut leader, mut follower) = create_mock_aes_gcm_pair(
            "test",
            &mut leader_vm,
            &mut follower_vm,
            leader_config,
            follower_config,
        )
        .await;

        futures::try_join!(
            leader.set_key(leader_key, leader_iv),
            follower.set_key(follower_key, follower_iv)
        )
        .unwrap();

        ((leader, follower), (leader_vm, follower_vm))
    }

    #[tokio::test]
    async fn test_aes_gcm_encrypt_private() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt_private(explicit_nonce.clone(), plaintext.clone(), aad.clone(),),
            follower.encrypt_blind(explicit_nonce.clone(), plaintext.len(), aad.clone())
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

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt_public(explicit_nonce.clone(), plaintext.clone(), aad.clone(),),
            follower.encrypt_public(explicit_nonce.clone(), plaintext.clone(), aad.clone(),)
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

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, _) = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), ciphertext, aad.clone(),)
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
        corrupted[len - 1] -= 1;

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        // leader receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), corrupted.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        // follower receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), corrupted.clone(), aad.clone(),)
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

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, follower_plaintext) = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), ciphertext, aad.clone(),)
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
        corrupted[len - 1] -= 1;

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        // leader receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), corrupted.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) =
            setup_pair(key.clone(), iv.clone()).await;

        // follower receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), corrupted.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));
    }
}
