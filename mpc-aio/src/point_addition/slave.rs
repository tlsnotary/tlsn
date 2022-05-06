use super::PointAdditionError;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::point_addition::{slave, PointAdditionMessage, SecretShare, SlaveCore};
use p256::EncodedPoint;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tracing::{instrument, trace};

pub struct PointAdditionSlave<S> {
    stream: S,
}

impl<
        S: Sink<PointAdditionMessage> + Stream<Item = Result<PointAdditionMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > PointAdditionSlave<S>
where
    PointAdditionError: From<<S as Sink<PointAdditionMessage>>::Error>,
    PointAdditionError: From<E>,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    #[instrument(skip(self, point))]
    pub async fn run(&mut self, point: &EncodedPoint) -> Result<SecretShare, PointAdditionError> {
        let mut slave = slave::PointAdditionSlave::new(point);

        // Step 1
        let master_message = match self.stream.next().await {
            Some(Ok(PointAdditionMessage::M1(m))) => PointAdditionMessage::M1(m),
            Some(Ok(m)) => return Err(PointAdditionError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received M1");
        let message = slave.next(master_message);
        if message.is_err() {
            // TODO: come up with a way to cleanly return the specific error
            return Err(PointAdditionError::UnderlyingError);
        }
        let message = message.unwrap();
        trace!("Sending S1");
        self.stream.send(message).await?;

        // Step 2
        let master_message = match self.stream.next().await {
            Some(Ok(PointAdditionMessage::M2(m))) => PointAdditionMessage::M2(m),
            Some(Ok(m)) => return Err(PointAdditionError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received M2");
        let message = slave.next(master_message);
        if message.is_err() {
            // TODO: come up with a way to cleanly return the specific error
            return Err(PointAdditionError::UnderlyingError);
        }
        let message = message.unwrap();
        trace!("Sending S2");
        self.stream.send(message).await?;

        // Complete
        let master_message = match self.stream.next().await {
            Some(Ok(PointAdditionMessage::M3(m))) => PointAdditionMessage::M3(m),
            Some(Ok(m)) => return Err(PointAdditionError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received M3");

        let message = slave.next(master_message);
        if message.is_err() {
            // TODO: come up with a way to cleanly return the specific error
            return Err(PointAdditionError::UnderlyingError);
        }
        let message = message.unwrap();
        trace!("Sending S3");
        self.stream.send(message).await?;

        Ok(slave.get_secret())
    }
}
