use std::sync::Arc;

use async_trait::async_trait;
use futures::{stream::FuturesOrdered, StreamExt};
use mpz_common::{Context, Task};
use mpz_core::commit::{Decommitment, HashCommit};
use serio::{stream::IoStreamExt, SinkExt};
use tlsn_common::ghash::build_ghash_data;

use crate::{
    decode::OneTimePadShared,
    record_layer::aead::{
        ghash::{Ghash, TagShare},
        AeadError,
    },
    Role,
};

pub(crate) struct VerifyTagData {
    pub(crate) j0: OneTimePadShared<[u8; 16]>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) tag: Vec<u8>,
}

#[must_use = "verify tags operation must be awaited"]
pub(crate) struct VerifyTags {
    role: Role,
    data: Vec<VerifyTagData>,
    /// MPC implementation to use for computing GHASH.
    ghash: Arc<dyn Ghash + Send + Sync>,
}

impl VerifyTags {
    pub(crate) fn new(
        role: Role,
        data: Vec<VerifyTagData>,
        ghash: Arc<dyn Ghash + Send + Sync>,
    ) -> Self {
        Self { role, data, ghash }
    }
}

#[async_trait]
impl Task for VerifyTags {
    type Output = Result<(), AeadError>;

    async fn run(self, ctx: &mut Context) -> Self::Output {
        let Self {
            role,
            mut data,
            ghash,
        } = self;

        if data.is_empty() {
            return Ok(());
        }

        let mut j0_shares = Vec::with_capacity(data.len());
        {
            let mut futs = FuturesOrdered::from_iter(data.iter_mut().map(|data| &mut data.j0));
            while let Some(j0_share) = futs.next().await.transpose().map_err(AeadError::tag)? {
                j0_shares.push(j0_share);
            }
        }

        let mut tag_shares = Vec::with_capacity(data.len());
        let mut tags = Vec::with_capacity(data.len());

        for (mut tag_share, data) in j0_shares.into_iter().zip(data) {
            let ghash_share = ghash
                .compute(&build_ghash_data(data.aad, data.ciphertext))
                .map_err(AeadError::tag)?;
            tag_share
                .iter_mut()
                .zip(ghash_share)
                .for_each(|(a, b)| *a ^= b);

            tag_shares.push(TagShare(tag_share));
            tags.push(data.tag);
        }

        let io = ctx.io_mut();
        let peer_tag_shares = match role {
            Role::Leader => {
                // Send commitment to follower.
                let (decommitment, commitment) = tag_shares.clone().hash_commit();

                io.send(commitment).await.map_err(AeadError::tag)?;

                let follower_tag_shares: Vec<TagShare> =
                    io.expect_next().await.map_err(AeadError::tag)?;

                if follower_tag_shares.len() != tag_shares.len() {
                    return Err(AeadError::tag("follower tag shares length mismatch"));
                }

                // Send decommitment to follower.
                io.send(decommitment).await.map_err(AeadError::tag)?;

                follower_tag_shares
            }
            Role::Follower => {
                // Wait for commitment from leader.
                let commitment = io.expect_next().await.map_err(AeadError::tag)?;

                // Send tag shares to leader.
                io.send(tag_shares.clone()).await.map_err(AeadError::tag)?;

                // Expect decommitment from leader.
                let decommitment: Decommitment<Vec<TagShare>> =
                    io.expect_next().await.map_err(AeadError::tag)?;

                // Verify decommitment.
                decommitment.verify(&commitment).map_err(AeadError::tag)?;

                decommitment.into_inner()
            }
        };

        let expected_tags = tag_shares
            .into_iter()
            .zip(peer_tag_shares)
            .map(|(tag_share, peer_tag_share)| tag_share + peer_tag_share)
            .collect::<Vec<_>>();

        if tags != expected_tags {
            return Err(AeadError::tag("failed to verify tags"));
        }

        Ok(())
    }

    async fn run_boxed(self: Box<Self>, ctx: &mut Context) -> Self::Output {
        self.run(ctx).await
    }
}
