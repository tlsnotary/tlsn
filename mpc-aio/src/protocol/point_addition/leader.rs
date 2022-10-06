use super::{PAChannel, PointAddition2PC, PointAdditionError};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::point_addition::{P256SecretShare, PointAdditionLeader, PointAdditionMessage};
use p256::EncodedPoint;
use tracing::{instrument, trace};
use utils_aio::expect_msg_or_err;

pub struct PaillierLeader {
    channel: PAChannel,
}

impl PaillierLeader {
    pub fn new(channel: PAChannel) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl PointAddition2PC for PaillierLeader {
    #[instrument(skip(self, point))]
    async fn add(&mut self, point: &EncodedPoint) -> Result<P256SecretShare, PointAdditionError> {
        trace!("Starting");
        let leader = PointAdditionLeader::new(point);

        let (msg, leader) = leader.next();

        self.channel.send(PointAdditionMessage::M1(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PointAdditionMessage::S1,
            PointAdditionError::UnexpectedMessage
        )?;
        let (msg, leader) = leader.next(msg);

        self.channel.send(PointAdditionMessage::M2(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PointAdditionMessage::S2,
            PointAdditionError::UnexpectedMessage
        )?;
        let (msg, leader) = leader.next(msg);

        self.channel.send(PointAdditionMessage::M3(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PointAdditionMessage::S3,
            PointAdditionError::UnexpectedMessage
        )?;

        trace!("Finished");
        Ok(leader.finalize(msg)?)
    }
}
