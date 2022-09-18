use super::{PAChannel, PointAddition2PC, PointAdditionError};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::point_addition::{P256SecretShare, PointAdditionLeader, PointAdditionMessage};
use p256::EncodedPoint;
use tracing::{instrument, trace};

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

        let msg = match self.channel.next().await {
            Some(PointAdditionMessage::S1(msg)) => msg,
            Some(m) => return Err(PointAdditionError::UnexpectedMessage(m)),
            None => {
                return Err(PointAdditionError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, leader) = leader.next(msg);

        self.channel.send(PointAdditionMessage::M2(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PointAdditionMessage::S2(msg)) => msg,
            Some(m) => return Err(PointAdditionError::UnexpectedMessage(m)),
            None => {
                return Err(PointAdditionError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, leader) = leader.next(msg);

        self.channel.send(PointAdditionMessage::M3(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PointAdditionMessage::S3(msg)) => msg,
            Some(m) => return Err(PointAdditionError::UnexpectedMessage(m)),
            None => {
                return Err(PointAdditionError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        trace!("Finished");
        Ok(leader.finalize(msg)?)
    }
}
