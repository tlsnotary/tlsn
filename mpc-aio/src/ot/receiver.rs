use super::errors::OtError;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{OtMessage, OtReceiveCore};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;

pub struct OtReceiver<OT, S> {
    ot: OT,
    stream: S,
}

#[async_trait]
pub trait OtReceive {
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OtError>;
}

impl<
        OT: OtReceiveCore + Send,
        S: Sink<OtMessage> + Stream<Item = Result<OtMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > OtReceiver<OT, S>
where
    OtError: From<<S as Sink<OtMessage>>::Error>,
    OtError: From<E>,
{
    pub fn new(ot: OT, stream: S) -> Self {
        Self { ot, stream }
    }
}

#[async_trait]
impl<
        OT: OtReceiveCore + Send,
        S: Sink<OtMessage> + Stream<Item = Result<OtMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > OtReceive for OtReceiver<OT, S>
where
    OtError: From<<S as Sink<OtMessage>>::Error>,
    OtError: From<E>,
{
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OtError> {
        let base_setup = self.ot.base_setup()?;

        self.stream
            .send(OtMessage::BaseSenderSetup(base_setup))
            .await?;

        let base_receiver_setup = match self.stream.next().await {
            Some(Ok(OtMessage::BaseReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let payload = self.ot.base_send(base_receiver_setup.try_into().unwrap())?;

        self.stream
            .send(OtMessage::BaseSenderPayload(payload))
            .await?;

        let setup = self.ot.extension_setup(choice)?;

        self.stream.send(OtMessage::ReceiverSetup(setup)).await?;

        let payload = match self.stream.next().await {
            Some(Ok(OtMessage::SenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let values = self.ot.receive(choice, payload.try_into().unwrap())?;

        Ok(values)
    }
}
