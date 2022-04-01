use super::errors::OtError;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{OtMessage, OtSendCore};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;

pub struct OtSender<OT, S> {
    ot: OT,
    stream: S,
}

#[async_trait]
pub trait OtSend {
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OtError>;
}

impl<
        OT: OtSendCore + Send,
        S: Sink<OtMessage> + Stream<Item = Result<OtMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > OtSender<OT, S>
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
        OT: OtSendCore + Send,
        S: Sink<OtMessage> + Stream<Item = Result<OtMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > OtSend for OtSender<OT, S>
where
    OtError: From<<S as Sink<OtMessage>>::Error>,
    OtError: From<E>,
{
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OtError> {
        let base_sender_setup = match self.stream.next().await {
            Some(Ok(OtMessage::BaseSenderSetup(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let base_setup = self.ot.base_setup(base_sender_setup.try_into().unwrap())?;

        self.stream
            .send(OtMessage::BaseReceiverSetup(base_setup))
            .await?;

        let base_payload = match self.stream.next().await {
            Some(Ok(OtMessage::BaseSenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        self.ot.base_receive(base_payload.try_into().unwrap())?;

        let extension_receiver_setup = match self.stream.next().await {
            Some(Ok(OtMessage::ReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        self.ot
            .extension_setup(extension_receiver_setup.try_into().unwrap())?;
        let payload = self.ot.send(payload)?;

        self.stream.send(OtMessage::SenderPayload(payload)).await?;

        Ok(())
    }
}
