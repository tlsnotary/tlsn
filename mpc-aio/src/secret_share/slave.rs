use super::SecretShareError;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::secret_share::{SecretShare, SecretShareMessage, SecretShareSlaveCore};
use p256::EncodedPoint;
use std::io::Error as IOError;
use std::io::ErrorKind;

pub struct SecretShareSlave<S> {
    stream: S,
}

impl<
        S: Sink<SecretShareMessage> + Stream<Item = Result<SecretShareMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > SecretShareSlave<S>
where
    SecretShareError: From<<S as Sink<SecretShareMessage>>::Error>,
    SecretShareError: From<E>,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub async fn run(&mut self, point: &EncodedPoint) -> Result<SecretShare, SecretShareError> {
        let slave = SecretShareSlaveCore::new(point);

        // Step 1
        let master_message = match self.stream.next().await {
            Some(Ok(SecretShareMessage::M1(m))) => m,
            Some(Ok(m)) => return Err(SecretShareError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        let (message, slave) = slave.next(master_message.into());
        self.stream.send(message.into()).await?;

        // Step 2
        let master_message = match self.stream.next().await {
            Some(Ok(SecretShareMessage::M2(m))) => m,
            Some(Ok(m)) => return Err(SecretShareError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        let (message, slave) = slave.next(master_message.into());
        self.stream.send(message.into()).await?;

        // Complete
        let master_message = match self.stream.next().await {
            Some(Ok(SecretShareMessage::M3(m))) => m,
            Some(Ok(m)) => return Err(SecretShareError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let (message, slave) = slave.next(master_message.into());
        self.stream.send(message.into()).await?;

        Ok(slave.secret())
    }
}
