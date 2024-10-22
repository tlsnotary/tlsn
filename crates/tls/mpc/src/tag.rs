use crate::{
    aes_gcm::{error::AesGcmError, MpcAesGcm},
    config::Role,
};
use mpz_common::Context;
use mpz_core::{
    commit::{Decommitment, HashCommit},
    hash::Hash,
};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Vector, ViewExt,
};
use mpz_vm_core::VmExt;
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};
use std::ops::Add;
use tlsn_universal_hash::UniversalHash;
use tracing::instrument;

pub(crate) const TAG_LEN: usize = 16;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tag([u8; TAG_LEN]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Add for Tag {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Tag(core::array::from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
}

impl<U> MpcAesGcm<U> {
    #[instrument(level = "trace", skip_all, err)]
    async fn compute_tag_share<Ctx, Vm>(
        &mut self,
        vm: &mut Vm,
        explicit_nonce: Array<U8, 8>,
        ciphertext: Vector<U8>,
        aad: Vec<U8>,
        ctx: &mut Ctx,
    ) -> Result<Tag, AesGcmError>
    where
        Ctx: Context,
        U: UniversalHash<Ctx>,
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let key = self.key()?;
        let iv = self.iv()?;

        // TODO: Commit to nonce and ciphertext

        let mac = match self.mac {
            Some(ref mut mac) => mac,
            None => &mut Self::prepare_mac(self.config.role(), vm, key, iv, 1)?,
        };

        let j0 = match mac.j0.pop_front() {
            Some(j0) => j0,
            None => Self::prepare_keystream(vm, key, iv)?,
        };
        // TODO: Get cleartext j0 and decode_share it
        // TODO: Compute hash

        let mac_key = mac.key;

        todo!()
    }

    /// Computes the tag for a ciphertext and additional data.
    ///
    /// The commit-reveal step is not required for computing a tag sent to the
    /// Server, as it will be able to detect if the tag is incorrect.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn add_tag_shares<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        share: Tag,
    ) -> Result<Tag, AesGcmError> {
        // TODO: The follower doesn't really need to learn the tag,
        // we could reduce some latency by not sending it.
        let io = ctx.io_mut();

        io.send(share).await?;
        let other_tag_share: Tag = io.expect_next().await?;

        let tag = share + other_tag_share;

        Ok(tag)
    }

    /// Verifies a purported tag against the ciphertext and additional data.
    ///
    /// Verifying a tag requires a commit-reveal protocol between the leader and
    /// follower. Without it, the party which receives the other's tag share first
    /// could trivially compute a tag share which would cause an invalid message to
    /// be accepted.
    #[instrument(level = "debug", skip_all, err)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn verify_tag<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        share: Tag,
        purported_tag: Tag,
    ) -> Result<(), AesGcmError> {
        let io = ctx.io_mut();
        let tag = match self.config.role() {
            Role::Leader => {
                // Send commitment of tag share to follower.
                let (decommitment, commitment) = share.hash_commit();

                io.send(commitment).await?;

                let follower_share: Tag = io.expect_next().await?;

                // Send decommitment (tag share) to follower.
                io.send(decommitment).await?;

                share + follower_share
            }
            Role::Follower => {
                // Wait for commitment from leader.
                let commitment: Hash = io.expect_next().await?;

                // Send tag share to leader.
                io.send(share).await?;

                // Expect decommitment (tag share) from leader.
                let decommitment: Decommitment<Tag> = io.expect_next().await?;

                // Verify decommitment.
                decommitment.verify(&commitment).map_err(|_| {
                    AesGcmError::peer("leader tag share commitment verification failed")
                })?;

                let leader_share = decommitment.into_inner();

                share + leader_share
            }
        };

        // Reject if tag is incorrect.
        if tag != purported_tag {
            return Err(AesGcmError::invalid_tag());
        }

        Ok(())
    }
}

/// Builds padded data for GHASH.
fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
    let associated_data_bitlen = (aad.len() as u64) * 8;
    let text_bitlen = (ciphertext.len() as u64) * 8;

    let len_block = ((associated_data_bitlen as u128) << 64) + (text_bitlen as u128);

    // Pad data to be a multiple of 16 bytes.
    let aad_padded_block_count = (aad.len() / 16) + (aad.len() % 16 != 0) as usize;
    aad.resize(aad_padded_block_count * 16, 0);

    let ciphertext_padded_block_count =
        (ciphertext.len() / 16) + (ciphertext.len() % 16 != 0) as usize;
    ciphertext.resize(ciphertext_padded_block_count * 16, 0);

    let mut data: Vec<u8> = Vec::with_capacity(aad.len() + ciphertext.len() + 16);
    data.extend(aad);
    data.extend(ciphertext);
    data.extend_from_slice(&len_block.to_be_bytes());

    data
}
