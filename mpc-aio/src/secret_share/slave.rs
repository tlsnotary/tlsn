use super::SecretShareError;
use crate::twopc::TwoPCProtocol;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::secret_share::{SecretShare, SecretShareMessage, SecretShareSlaveCore};
use p256::EncodedPoint;
use std::io::Error as IOError;
use std::io::ErrorKind;

pub struct SecretShareSlave;

impl SecretShareSlave {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TwoPCProtocol<SecretShareMessage> for SecretShareSlave {
    type Input = EncodedPoint;
    type Error = SecretShareError;
    type Output = SecretShare;

    async fn run<
        S: Sink<SecretShareMessage> + Stream<Item = Result<SecretShareMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    >(
        &mut self,
        stream: &mut S,
        input: Self::Input,
    ) -> Result<SecretShare, SecretShareError>
    where
        Self::Error: From<<S as Sink<SecretShareMessage>>::Error>,
        Self::Error: From<E>,
    {
        let slave = SecretShareSlaveCore::new(&input);

        // Step 1
        let master_message = match stream.next().await {
            Some(Ok(SecretShareMessage::M1(m))) => m,
            Some(Ok(m)) => return Err(SecretShareError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        let (message, slave) = slave.next(master_message.into());
        stream.send(message.into()).await?;

        // Step 2
        let master_message = match stream.next().await {
            Some(Ok(SecretShareMessage::M2(m))) => m,
            Some(Ok(m)) => return Err(SecretShareError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        let (message, slave) = slave.next(master_message.into());
        stream.send(message.into()).await?;

        // Complete
        let master_message = match stream.next().await {
            Some(Ok(SecretShareMessage::M3(m))) => m,
            Some(Ok(m)) => return Err(SecretShareError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let (message, slave) = slave.next(master_message.into());
        stream.send(message.into()).await?;

        Ok(slave.secret())
    }
}
