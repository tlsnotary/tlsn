//! This module provides an implementation of 2PC AES-GCM.

mod config;
mod error;
#[cfg(feature = "mock")]
pub mod mock;
mod tag;

pub use config::{AesGcmConfig, AesGcmConfigBuilder, AesGcmConfigBuilderError, Role};
pub use error::AesGcmError;

use async_trait::async_trait;
use block_cipher::{Aes128, BlockCipher};
use futures::TryFutureExt;
use mpz_common::Context;
use mpz_garble::value::ValueRef;
use tlsn_stream_cipher::{Aes128Ctr, StreamCipher};
use tlsn_universal_hash::UniversalHash;
use tracing::instrument;

use crate::{
    aes_gcm::tag::{compute_tag, verify_tag, TAG_LEN},
    Aead,
};

/// MPC AES-GCM.
pub struct MpcAesGcm<Ctx> {
    config: AesGcmConfig,
    ctx: Ctx,
    aes_block: Box<dyn BlockCipher<Aes128>>,
    aes_ctr: Box<dyn StreamCipher<Aes128Ctr>>,
    ghash: Box<dyn UniversalHash>,
}

impl<Ctx> std::fmt::Debug for MpcAesGcm<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAesGcm")
            .field("config", &self.config)
            .finish()
    }
}

impl<Ctx: Context> MpcAesGcm<Ctx> {
    /// Creates a new instance of [`MpcAesGcm`].
    pub fn new(
        config: AesGcmConfig,
        context: Ctx,
        aes_block: Box<dyn BlockCipher<Aes128>>,
        aes_ctr: Box<dyn StreamCipher<Aes128Ctr>>,
        ghash: Box<dyn UniversalHash>,
    ) -> Self {
        Self {
            config,
            ctx: context,
            aes_block,
            aes_ctr,
            ghash,
        }
    }
}

#[async_trait]
impl<Ctx: Context> Aead for MpcAesGcm<Ctx> {
    type Error = AesGcmError;

    #[instrument(level = "info", skip_all, err)]
    async fn set_key(&mut self, key: ValueRef, iv: ValueRef) -> Result<(), AesGcmError> {
        self.aes_block.set_key(key.clone());
        self.aes_ctr.set_key(key, iv);

        Ok(())
    }

    #[instrument(level = "info", skip_all, err)]
    async fn decode_key_private(&mut self) -> Result<(), AesGcmError> {
        self.aes_ctr
            .decode_key_private()
            .await
            .map_err(AesGcmError::from)
    }

    #[instrument(level = "info", skip_all, err)]
    async fn decode_key_blind(&mut self) -> Result<(), AesGcmError> {
        self.aes_ctr
            .decode_key_blind()
            .await
            .map_err(AesGcmError::from)
    }

    fn set_transcript_id(&mut self, id: &str) {
        self.aes_ctr.set_transcript_id(id)
    }

    #[instrument(level = "debug", skip(self), err)]
    async fn setup(&mut self) -> Result<(), AesGcmError> {
        self.ghash.setup().await?;

        Ok(())
    }

    #[instrument(level = "debug", skip(self), err)]
    async fn preprocess(&mut self, len: usize) -> Result<(), AesGcmError> {
        futures::try_join!(
            // Preprocess the GHASH key block.
            self.aes_block
                .preprocess(block_cipher::Visibility::Public, 1)
                .map_err(AesGcmError::from),
            self.aes_ctr.preprocess(len).map_err(AesGcmError::from),
            self.ghash.preprocess().map_err(AesGcmError::from),
        )?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn start(&mut self) -> Result<(), AesGcmError> {
        let h_share = self.aes_block.encrypt_share(vec![0u8; 16]).await?;
        self.ghash.set_key(h_share).await?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AesGcmError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_public(explicit_nonce.clone(), plaintext)
            .await?;

        let tag = compute_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            explicit_nonce,
            ciphertext.clone(),
            aad,
        )
        .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AesGcmError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_private(explicit_nonce.clone(), plaintext)
            .await?;

        let tag = compute_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            explicit_nonce,
            ciphertext.clone(),
            aad,
        )
        .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext_len: usize,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AesGcmError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_blind(explicit_nonce.clone(), plaintext_len)
            .await?;

        let tag = compute_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            explicit_nonce,
            ciphertext.clone(),
            aad,
        )
        .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AesGcmError> {
        let purported_tag: [u8; TAG_LEN] = payload
            .split_off(payload.len() - TAG_LEN)
            .try_into()
            .map_err(|_| AesGcmError::payload("payload is not long enough to contain tag"))?;
        let ciphertext = payload;

        verify_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            *self.config.role(),
            explicit_nonce.clone(),
            ciphertext.clone(),
            aad,
            purported_tag,
        )
        .await?;

        let plaintext = self
            .aes_ctr
            .decrypt_public(explicit_nonce, ciphertext)
            .await?;

        Ok(plaintext)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AesGcmError> {
        let purported_tag: [u8; TAG_LEN] = payload
            .split_off(payload.len() - TAG_LEN)
            .try_into()
            .map_err(|_| AesGcmError::payload("payload is not long enough to contain tag"))?;
        let ciphertext = payload;

        verify_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            *self.config.role(),
            explicit_nonce.clone(),
            ciphertext.clone(),
            aad,
            purported_tag,
        )
        .await?;

        let plaintext = self
            .aes_ctr
            .decrypt_private(explicit_nonce, ciphertext)
            .await?;

        Ok(plaintext)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AesGcmError> {
        let purported_tag: [u8; TAG_LEN] = payload
            .split_off(payload.len() - TAG_LEN)
            .try_into()
            .map_err(|_| AesGcmError::payload("payload is not long enough to contain tag"))?;
        let ciphertext = payload;

        verify_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            *self.config.role(),
            explicit_nonce.clone(),
            ciphertext.clone(),
            aad,
            purported_tag,
        )
        .await?;

        self.aes_ctr
            .decrypt_blind(explicit_nonce, ciphertext)
            .await?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn verify_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AesGcmError> {
        let purported_tag: [u8; TAG_LEN] = payload
            .split_off(payload.len() - TAG_LEN)
            .try_into()
            .map_err(|_| AesGcmError::payload("payload is not long enough to contain tag"))?;
        let ciphertext = payload;

        verify_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            *self.config.role(),
            explicit_nonce,
            ciphertext,
            aad,
            purported_tag,
        )
        .await?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn prove_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AesGcmError> {
        let purported_tag: [u8; TAG_LEN] = payload
            .split_off(payload.len() - TAG_LEN)
            .try_into()
            .map_err(|_| AesGcmError::payload("payload is not long enough to contain tag"))?;
        let ciphertext = payload;

        verify_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            *self.config.role(),
            explicit_nonce.clone(),
            ciphertext.clone(),
            aad,
            purported_tag,
        )
        .await?;

        let plaintext = self
            .aes_ctr
            .prove_plaintext(explicit_nonce, ciphertext)
            .await?;

        Ok(plaintext)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn prove_plaintext_no_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, AesGcmError> {
        self.aes_ctr
            .prove_plaintext(explicit_nonce, ciphertext)
            .map_err(AesGcmError::from)
            .await
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn verify_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AesGcmError> {
        let purported_tag: [u8; TAG_LEN] = payload
            .split_off(payload.len() - TAG_LEN)
            .try_into()
            .map_err(|_| AesGcmError::payload("payload is not long enough to contain tag"))?;
        let ciphertext = payload;

        verify_tag(
            &mut self.ctx,
            self.aes_ctr.as_mut(),
            self.ghash.as_mut(),
            *self.config.role(),
            explicit_nonce.clone(),
            ciphertext.clone(),
            aad,
            purported_tag,
        )
        .await?;

        self.aes_ctr
            .verify_plaintext(explicit_nonce, ciphertext)
            .await?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn verify_plaintext_no_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<(), AesGcmError> {
        self.aes_ctr
            .verify_plaintext(explicit_nonce, ciphertext)
            .map_err(AesGcmError::from)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aes_gcm::{mock::create_mock_aes_gcm_pair, AesGcmConfigBuilder, Role},
        Aead,
    };
    use ::aes_gcm::{aead::AeadInPlace, Aes128Gcm, NewAead, Nonce};
    use error::ErrorKind;
    use mpz_common::executor::STExecutor;
    use mpz_garble::{protocol::deap::mock::create_mock_deap_vm, Memory};
    use serio::channel::MemoryDuplex;

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
    ) -> (
        MpcAesGcm<STExecutor<MemoryDuplex>>,
        MpcAesGcm<STExecutor<MemoryDuplex>>,
    ) {
        let (leader_vm, follower_vm) = create_mock_deap_vm();

        let leader_key = leader_vm
            .new_public_array_input::<u8>("key", key.len())
            .unwrap();
        let leader_iv = leader_vm
            .new_public_array_input::<u8>("iv", iv.len())
            .unwrap();

        leader_vm.assign(&leader_key, key.clone()).unwrap();
        leader_vm.assign(&leader_iv, iv.clone()).unwrap();

        let follower_key = follower_vm
            .new_public_array_input::<u8>("key", key.len())
            .unwrap();
        let follower_iv = follower_vm
            .new_public_array_input::<u8>("iv", iv.len())
            .unwrap();

        follower_vm.assign(&follower_key, key.clone()).unwrap();
        follower_vm.assign(&follower_iv, iv.clone()).unwrap();

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
            (leader_vm, follower_vm),
            leader_config,
            follower_config,
        )
        .await;

        futures::try_join!(
            leader.set_key(leader_key, leader_iv),
            follower.set_key(follower_key, follower_iv)
        )
        .unwrap();

        futures::try_join!(leader.setup(), follower.setup()).unwrap();
        futures::try_join!(leader.start(), follower.start()).unwrap();

        (leader, follower)
    }

    #[tokio::test]
    #[ignore = "expensive"]
    async fn test_aes_gcm_encrypt_private() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

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
    #[ignore = "expensive"]
    async fn test_aes_gcm_encrypt_public() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

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
    #[ignore = "expensive"]
    async fn test_aes_gcm_decrypt_private() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, _) = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), ciphertext, aad.clone(),)
        )
        .unwrap();

        assert_eq!(leader_plaintext, plaintext);
    }

    #[tokio::test]
    #[ignore = "expensive"]
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

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // leader receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), corrupted.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Tag);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // follower receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), corrupted.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Tag);
    }

    #[tokio::test]
    #[ignore = "expensive"]
    async fn test_aes_gcm_decrypt_public() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, follower_plaintext) = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), ciphertext, aad.clone(),)
        )
        .unwrap();

        assert_eq!(leader_plaintext, plaintext);
        assert_eq!(leader_plaintext, follower_plaintext);
    }

    #[tokio::test]
    #[ignore = "expensive"]
    async fn test_aes_gcm_decrypt_public_bad_tag() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let len = ciphertext.len();

        // Corrupt tag.
        let mut corrupted = ciphertext.clone();
        corrupted[len - 1] -= 1;

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // Leader receives corrupted tag.
        let err = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), corrupted.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Tag);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // Follower receives corrupted tag.
        let err = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), corrupted.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Tag);
    }

    #[tokio::test]
    #[ignore = "expensive"]
    async fn test_aes_gcm_verify_tag() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let len = ciphertext.len();

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        tokio::try_join!(
            leader.verify_tag(explicit_nonce.clone(), ciphertext.clone(), aad.clone()),
            follower.verify_tag(explicit_nonce.clone(), ciphertext.clone(), aad.clone())
        )
        .unwrap();

        //Corrupt tag.
        let mut corrupted = ciphertext.clone();
        corrupted[len - 1] -= 1;

        let (leader_res, follower_res) = tokio::join!(
            leader.verify_tag(explicit_nonce.clone(), corrupted.clone(), aad.clone()),
            follower.verify_tag(explicit_nonce.clone(), corrupted, aad.clone())
        );

        assert_eq!(leader_res.unwrap_err().kind(), ErrorKind::Tag);
        assert_eq!(follower_res.unwrap_err().kind(), ErrorKind::Tag);
    }
}
