use super::{PointAddition2PC, PointAdditionError};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::point_addition::{master, MasterCore, PointAdditionMessage, SecretShare};
use mpc_core::proto::point_addition::PointAdditionMessage as ProtoMessage;
use p256::EncodedPoint;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::{instrument, trace};
use utils_aio::codec::ProstCodecDelimited;

pub struct PaillierLeader<S> {
    stream: Framed<S, ProstCodecDelimited<PointAdditionMessage, ProtoMessage>>,
}

impl<S> PaillierLeader<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: Framed::new(
                stream,
                ProstCodecDelimited::<PointAdditionMessage, ProtoMessage>::default(),
            ),
        }
    }
}

#[async_trait]
impl<S> PointAddition2PC for PaillierLeader<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    #[instrument(skip(self, point))]
    async fn add(&mut self, point: &EncodedPoint) -> Result<SecretShare, PointAdditionError> {
        trace!("Starting");
        let mut master = master::PointAdditionMaster::new(point);

        let mut slave_message: Option<PointAdditionMessage> = None;
        loop {
            if let Some(message) = master.next(slave_message)? {
                self.stream.send(message).await?;
                trace!("Sent message");
            }
            if master.is_complete() {
                break;
            }
            slave_message = Some(
                self.stream
                    .next()
                    .await
                    .ok_or(IOError::new(ErrorKind::UnexpectedEof, ""))??,
            );
            trace!("Received message");
        }

        trace!("Finished");
        Ok(master.get_secret()?)
    }
}
