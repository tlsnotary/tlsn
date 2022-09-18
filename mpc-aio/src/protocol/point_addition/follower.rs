use super::{PAChannel, PointAddition2PC, PointAdditionError};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::point_addition::{P256SecretShare, PointAdditionFollower, PointAdditionMessage};
use p256::EncodedPoint;
use tracing::{instrument, trace};

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

        let msg = match self.channel.next().await {
            Some(PointAdditionMessage::M1(msg)) => msg,
            Some(m) => return Err(PointAdditionError::UnexpectedMessage(m)),
            None => {
                return Err(PointAdditionError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, follower) = follower.next(msg);

        self.channel.send(PointAdditionMessage::S1(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PointAdditionMessage::M2(msg)) => msg,
            Some(m) => return Err(PointAdditionError::UnexpectedMessage(m)),
            None => {
                return Err(PointAdditionError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, follower) = follower.next(msg);

        self.channel.send(PointAdditionMessage::S2(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PointAdditionMessage::M3(msg)) => msg,
            Some(m) => return Err(PointAdditionError::UnexpectedMessage(m)),
            None => {
                return Err(PointAdditionError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, follower) = follower.next(msg);

        self.channel.send(PointAdditionMessage::S3(msg)).await?;

        trace!("Finished");
        Ok(follower.finalize()?)
    }
}
