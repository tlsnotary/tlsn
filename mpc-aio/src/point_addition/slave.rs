use super::PointAdditionError;
use futures::{SinkExt, StreamExt};
use mpc_core::point_addition::{slave, PointAdditionMessage, SecretShare, SlaveCore};
use mpc_core::proto::point_addition::PointAdditionMessage as ProtoMessage;
use p256::EncodedPoint;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::{instrument, trace};
use utils_aio::codec::ProstCodecDelimited;

pub struct PointAdditionSlave<S> {
    stream: Framed<S, ProstCodecDelimited<PointAdditionMessage, ProtoMessage>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> PointAdditionSlave<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream: Framed::new(
                stream,
                ProstCodecDelimited::<PointAdditionMessage, ProtoMessage>::default(),
            ),
        }
    }

    #[instrument(skip(self, point))]
    pub async fn run(&mut self, point: &EncodedPoint) -> Result<SecretShare, PointAdditionError> {
        trace!("Starting");
        let mut slave = slave::PointAdditionSlave::new(point);

        let mut master_message;
        loop {
            master_message = Some(
                self.stream
                    .next()
                    .await
                    .ok_or(IOError::new(ErrorKind::UnexpectedEof, ""))??,
            );
            trace!("Received Message");
            if let Some(message) = slave.next(master_message)? {
                self.stream.send(message).await?;
                trace!("Sent Message");
            }
            if slave.is_complete() {
                break;
            }
        }

        trace!("Finished");
        Ok(slave.get_secret()?)
    }
}
