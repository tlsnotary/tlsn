use std::{future::Future, pin::Pin, sync::Arc};

use async_trait::async_trait;
use futures::{stream::FuturesOrdered, StreamExt as _};
use mpz_common::{Context, Task};
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

pub(crate) struct ComputeTagData {
    pub(crate) j0: OneTimePadShared<[u8; 16]>,
    pub(crate) ciphertext: Pin<Box<dyn Future<Output = Result<Vec<u8>, AeadError>> + Send + Sync>>,
    pub(crate) aad: Vec<u8>,
}

#[must_use = "compute tags operation must be awaited"]
pub(crate) struct ComputeTags {
    role: Role,
    data: Vec<ComputeTagData>,
    ghash: Arc<dyn Ghash + Send + Sync>,
}

impl ComputeTags {
    pub(crate) fn new(
        role: Role,
        data: Vec<ComputeTagData>,
        ghash: Arc<dyn Ghash + Send + Sync>,
    ) -> Self {
        Self { role, data, ghash }
    }
}

#[async_trait]
impl Task for ComputeTags {
    type Output = Result<Option<Vec<Vec<u8>>>, AeadError>;

    async fn run(self, ctx: &mut Context) -> Self::Output {
        let Self {
            role,
            mut data,
            ghash,
        } = self;

        if data.is_empty() {
            return Ok(None);
        }

        let mut j0_shares = Vec::with_capacity(data.len());
        {
            let mut futs = FuturesOrdered::from_iter(data.iter_mut().map(|data| &mut data.j0));
            while let Some(j0_share) = futs.next().await.transpose().map_err(AeadError::tag)? {
                j0_shares.push(j0_share);
            }
        }

        let mut ciphertexts = Vec::with_capacity(data.len());
        {
            let mut futs =
                FuturesOrdered::from_iter(data.iter_mut().map(|data| &mut data.ciphertext));
            while let Some(ciphertext) = futs.next().await.transpose().map_err(AeadError::tag)? {
                ciphertexts.push(ciphertext);
            }
        }

        let mut tag_shares = Vec::with_capacity(data.len());
        for ((mut tag_share, ciphertext), data) in j0_shares.into_iter().zip(ciphertexts).zip(data)
        {
            let ghash_share = ghash
                .compute(&build_ghash_data(data.aad, ciphertext))
                .map_err(AeadError::tag)?;
            tag_share
                .iter_mut()
                .zip(ghash_share)
                .for_each(|(a, b)| *a ^= b);

            tag_shares.push(TagShare(tag_share));
        }

        let tags = match role {
            Role::Leader => {
                let follower_tag_shares: Vec<TagShare> =
                    ctx.io_mut().expect_next().await.map_err(AeadError::tag)?;

                if follower_tag_shares.len() != tag_shares.len() {
                    return Err(AeadError::tag("follower tag shares length mismatch"));
                }

                let tags = tag_shares
                    .into_iter()
                    .zip(follower_tag_shares)
                    .map(|(a, b)| a + b)
                    .collect();

                Some(tags)
            }
            Role::Follower => {
                ctx.io_mut()
                    .send(tag_shares)
                    .await
                    .map_err(AeadError::tag)?;

                None
            }
        };

        Ok(tags)
    }

    async fn run_boxed(self: Box<Self>, ctx: &mut Context) -> Self::Output {
        self.run(ctx).await
    }
}
