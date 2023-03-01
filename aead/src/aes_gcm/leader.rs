use super::{config::AesGcmLeaderConfig, AesGcmTagShare, AES_GCM_TAG_LEN};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use rand::Rng;
use tlsn_universal_hash::UniversalHash;

use block_cipher::{Aes128, BlockCipher};
use tlsn_stream_cipher::{cipher::Aes128Ctr, StreamCipherLeader};
use utils_aio::expect_msg_or_err;

use crate::{msg::AeadMessage, AeadChannel, AeadError, AeadLabels, AeadLeader};

pub struct AesGcmLeader<BC, SC, H>
where
    BC: BlockCipher<Aes128>,
    SC: StreamCipherLeader<Aes128Ctr>,
    H: UniversalHash,
{
    #[allow(dead_code)]
    config: AesGcmLeaderConfig,

    channel: AeadChannel,

    aes_block: BC,
    aes_ctr: SC,
    ghash: H,
}

impl<BC, SC, H> AesGcmLeader<BC, SC, H>
where
    BC: BlockCipher<Aes128>,
    SC: StreamCipherLeader<Aes128Ctr>,
    H: UniversalHash,
{
    pub fn new(
        config: AesGcmLeaderConfig,
        channel: AeadChannel,
        aes_block: BC,
        aes_ctr: SC,
        ghash: H,
    ) -> Self {
        Self {
            config,
            channel,
            aes_block,
            aes_ctr,
            ghash,
        }
    }

    async fn compute_j0_share(&mut self, explicit_nonce: Vec<u8>) -> Result<Vec<u8>, AeadError> {
        let j0_share = self
            .aes_ctr
            .share_key_block(explicit_nonce.clone(), 1)
            .await?;

        Ok(j0_share)
    }

    async fn compute_tag_share(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut aad: Vec<u8>,
        mut ciphertext: Vec<u8>,
    ) -> Result<AesGcmTagShare, AeadError> {
        let j0_share = self.compute_j0_share(explicit_nonce.clone()).await?;

        let associated_data_bitlen = (aad.len() as u64) * 8;
        let text_bitlen = (ciphertext.len() as u64) * 8;

        let len_block = ((associated_data_bitlen as u128) << 64) + (text_bitlen as u128);

        // pad data to be a multiple of 16 bytes
        let aad_padded_block_count = (aad.len() / 16) + (aad.len() % 16 != 0) as usize;
        aad.resize(aad_padded_block_count * 16, 0);

        let ciphertext_padded_block_count =
            (ciphertext.len() / 16) + (ciphertext.len() % 16 != 0) as usize;
        ciphertext.resize(ciphertext_padded_block_count * 16, 0);

        let mut data: Vec<u8> = Vec::with_capacity(aad.len() + ciphertext.len() + 8);
        data.extend(aad);
        data.extend(ciphertext);
        data.extend_from_slice(&len_block.to_be_bytes());

        let hash = self.ghash.finalize(data).await?;

        let mut tag_share = [0u8; 16];
        tag_share.copy_from_slice(&hash[..]);
        for i in 0..16 {
            tag_share[i] ^= j0_share[i];
        }

        Ok(AesGcmTagShare(tag_share))
    }

    async fn compute_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let tag_share = self
            .compute_tag_share(explicit_nonce, aad, ciphertext.clone())
            .await?;

        // Expect tag share from follower
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            AeadMessage::TagShare,
            AeadError::UnexpectedMessage
        )?;

        let other_tag_share = AesGcmTagShare::from_unchecked(msg.into())?;

        // Send tag share to follower
        self.channel
            .send(AeadMessage::TagShare(tag_share.into()))
            .await?;

        let tag = tag_share + other_tag_share;

        Ok(tag)
    }

    async fn encrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
        private: bool,
    ) -> Result<Vec<u8>, AeadError> {
        let ciphertext = if private {
            self.aes_ctr
                .encrypt_private(explicit_nonce.clone(), plaintext, record)
                .await?
        } else {
            self.aes_ctr
                .encrypt(explicit_nonce.clone(), plaintext, record)
                .await?
        };

        let tag = self
            .compute_tag(explicit_nonce, ciphertext.clone(), aad)
            .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    async fn decrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut ciphertext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
        private: bool,
    ) -> Result<Vec<u8>, AeadError> {
        let purported_tag = ciphertext.split_off(ciphertext.len() - AES_GCM_TAG_LEN);

        let tag = self
            .compute_tag(explicit_nonce.clone(), ciphertext.clone(), aad)
            .await?;

        // Reject if tag is incorrect
        if tag != purported_tag {
            return Err(AeadError::CorruptedTag);
        }

        let plaintext = if private {
            self.aes_ctr
                .decrypt_private(explicit_nonce, ciphertext, record)
                .await?
        } else {
            self.aes_ctr
                .decrypt(explicit_nonce, ciphertext, record)
                .await?
        };

        Ok(plaintext)
    }
}

#[async_trait]
impl<BC, SC, H> AeadLeader for AesGcmLeader<BC, SC, H>
where
    BC: BlockCipher<Aes128> + Send,
    SC: StreamCipherLeader<Aes128Ctr> + Send,
    H: UniversalHash + Send,
{
    async fn set_keys(&mut self, labels: AeadLabels) -> Result<(), AeadError> {
        self.aes_block.set_keys(labels.clone().into());
        self.aes_ctr.set_keys(labels.into());

        let mut mask = vec![0u8; 16];
        rand::thread_rng().fill(&mut mask[..]);

        // Encrypt zero block, applying mask
        let h_share = self.aes_block.encrypt_share(vec![0u8; 16], mask).await?;

        self.ghash.set_key(h_share).await?;

        Ok(())
    }

    async fn encrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError> {
        self.encrypt(explicit_nonce, plaintext, aad, record, false)
            .await
    }

    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError> {
        self.encrypt(explicit_nonce, plaintext, aad, record, true)
            .await
    }

    async fn decrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError> {
        self.decrypt(explicit_nonce, ciphertext, aad, record, false)
            .await
    }

    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, AeadError> {
        self.decrypt(explicit_nonce, ciphertext, aad, record, true)
            .await
    }
}
