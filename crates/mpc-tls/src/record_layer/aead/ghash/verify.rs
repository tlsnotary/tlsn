use std::sync::Arc;

use async_trait::async_trait;
use futures::{stream::FuturesOrdered, StreamExt};
use mpz_common::{Context, Task};
use serio::{stream::IoStreamExt, SinkExt};

use crate::{
    decode::OneTimePadShared,
    record_layer::aead::{
        ghash::{build_ghash_data, Ghash, TagShare},
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
        match role {
            Role::Leader => {
                let peer_tag_shares: Vec<TagShare> =
                    io.expect_next().await.map_err(AeadError::tag)?;

                if peer_tag_shares.len() != tag_shares.len() {
                    return Err(AeadError::tag("follower tag shares length mismatch"));
                }

                let expected_tags = tag_shares
                    .into_iter()
                    .zip(peer_tag_shares)
                    .map(|(tag_share, peer_tag_share)| tag_share + peer_tag_share)
                    .collect::<Vec<_>>();

                if tags != expected_tags {
                    return Err(AeadError::tag("failed to verify tags"));
                }
            }
            Role::Follower => {
                // Send tag shares to leader.
                io.send(tag_shares).await.map_err(AeadError::tag)?;
            }
        }

        Ok(())
    }

    async fn run_boxed(self: Box<Self>, ctx: &mut Context) -> Self::Output {
        self.run(ctx).await
    }
}
