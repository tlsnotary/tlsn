use super::{PAChannel, PointAddition2PC, PointAdditionError};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::point_addition::{P256SecretShare, PointAdditionFollower, PointAdditionMessage};
use p256::EncodedPoint;
use tracing::{instrument, trace};
use utils_aio::expect_msg_or_err;

pub struct PaillierFollower {
    channel: PAChannel,
}

impl PaillierFollower {
    pub fn new(channel: PAChannel) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl PointAddition2PC for PaillierFollower {
    #[instrument(skip(self, point))]
    async fn add(&mut self, point: &EncodedPoint) -> Result<P256SecretShare, PointAdditionError> {
        trace!("Starting");
        let follower = PointAdditionFollower::new(point);

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PointAdditionMessage::M1,
            PointAdditionError::UnexpectedMessage
        )?;
        let (msg, follower) = follower.next(msg);

        self.channel.send(PointAdditionMessage::S1(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PointAdditionMessage::M2,
            PointAdditionError::UnexpectedMessage
        )?;
        let (msg, follower) = follower.next(msg);

        self.channel.send(PointAdditionMessage::S2(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PointAdditionMessage::M3,
            PointAdditionError::UnexpectedMessage
        )?;
        let (msg, follower) = follower.next(msg);

        self.channel.send(PointAdditionMessage::S3(msg)).await?;

        trace!("Finished");
        Ok(follower.finalize()?)
    }
}
