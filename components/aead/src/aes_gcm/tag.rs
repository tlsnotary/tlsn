use futures::TryFutureExt;
use mpz_common::Context;
use mpz_core::{
    commit::{Decommitment, HashCommit},
    hash::Hash,
};
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};
use std::ops::Add;
use tlsn_stream_cipher::{Aes128Ctr, StreamCipher};
use tlsn_universal_hash::UniversalHash;
use tracing::instrument;

use crate::aes_gcm::{AesGcmError, Role};

pub(crate) const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TagShare([u8; TAG_LEN]);

impl AsRef<[u8]> for TagShare {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Add for TagShare {
    type Output = [u8; TAG_LEN];

    fn add(self, rhs: Self) -> Self::Output {
        core::array::from_fn(|i| self.0[i] ^ rhs.0[i])
    }
}

#[instrument(level = "trace", skip_all, err)]
async fn compute_tag_share<C: StreamCipher<Aes128Ctr> + ?Sized, H: UniversalHash + ?Sized>(
    aes_ctr: &mut C,
    hasher: &mut H,
    explicit_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<TagShare, AesGcmError> {
    let (j0, hash) = futures::try_join!(
        aes_ctr
            .share_keystream_block(explicit_nonce, 1)
            .map_err(AesGcmError::from),
        hasher
            .finalize(build_ghash_data(aad, ciphertext))
            .map_err(AesGcmError::from)
    )?;

    debug_assert!(j0.len() == TAG_LEN);
    debug_assert!(hash.len() == TAG_LEN);

    let tag_share = core::array::from_fn(|i| j0[i] ^ hash[i]);

    Ok(TagShare(tag_share))
}

/// Computes the tag for a ciphertext and additional data.
///
/// The commit-reveal step is not required for computing a tag sent to the Server, as it
/// will be able to detect if the tag is incorrect.
#[instrument(level = "debug", skip_all, err)]
pub(crate) async fn compute_tag<
    Ctx: Context,
    C: StreamCipher<Aes128Ctr> + ?Sized,
    H: UniversalHash + ?Sized,
>(
    ctx: &mut Ctx,
    aes_ctr: &mut C,
    hasher: &mut H,
    explicit_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<[u8; TAG_LEN], AesGcmError> {
    let tag_share = compute_tag_share(aes_ctr, hasher, explicit_nonce, ciphertext, aad).await?;

    // TODO: The follower doesn't really need to learn the tag,
    // we could reduce some latency by not sending it.
    let io = ctx.io_mut();
    io.send(tag_share.clone()).await?;
    let other_tag_share: TagShare = io.expect_next().await?;

    let tag = tag_share + other_tag_share;

    Ok(tag)
}

/// Verifies a purported tag against the ciphertext and additional data.
///
/// Verifying a tag requires a commit-reveal protocol between the leader and follower.
/// Without it, the party which receives the other's tag share first could trivially compute
/// a tag share which would cause an invalid message to be accepted.
#[instrument(level = "debug", skip_all, err)]
pub(crate) async fn verify_tag<
    Ctx: Context,
    C: StreamCipher<Aes128Ctr> + ?Sized,
    H: UniversalHash + ?Sized,
>(
    ctx: &mut Ctx,
    aes_ctr: &mut C,
    hasher: &mut H,
    role: Role,
    explicit_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
    purported_tag: [u8; TAG_LEN],
) -> Result<(), AesGcmError> {
    let tag_share = compute_tag_share(aes_ctr, hasher, explicit_nonce, ciphertext, aad).await?;

    let io = ctx.io_mut();
    let tag = match role {
        Role::Leader => {
            // Send commitment of tag share to follower.
            let (tag_share_decommitment, tag_share_commitment) = tag_share.clone().hash_commit();

            io.send(tag_share_commitment).await?;

            let follower_tag_share: TagShare = io.expect_next().await?;

            // Send decommitment (tag share) to follower.
            io.send(tag_share_decommitment).await?;

            tag_share + follower_tag_share
        }
        Role::Follower => {
            // Wait for commitment from leader.
            let commitment: Hash = io.expect_next().await?;

            // Send tag share to leader.
            io.send(tag_share.clone()).await?;

            // Expect decommitment (tag share) from leader.
            let decommitment: Decommitment<TagShare> = io.expect_next().await?;

            // Verify decommitment.
            decommitment.verify(&commitment).map_err(|_| {
                AesGcmError::peer("leader tag share commitment verification failed")
            })?;

            let leader_tag_share = decommitment.into_inner();

            tag_share + leader_tag_share
        }
    };

    // Reject if tag is incorrect.
    if tag != purported_tag {
        return Err(AesGcmError::invalid_tag());
    }

    Ok(())
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
