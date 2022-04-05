use super::OTError;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{ExtSendCore, Message};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tracing::{instrument, trace};

pub struct ExtSender<OT, S> {
    ot: OT,
    stream: S,
}

#[async_trait]
pub trait ExtOTSend {
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OTError>;
}

impl<
        OT: ExtSendCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > ExtSender<OT, S>
where
    OTError: From<<S as Sink<Message>>::Error>,
    OTError: From<E>,
{
    pub fn new(ot: OT, stream: S) -> Self {
        Self { ot, stream }
    }
}

#[async_trait]
impl<
        OT: ExtSendCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > ExtOTSend for ExtSender<OT, S>
where
    OTError: From<<S as Sink<Message>>::Error>,
    OTError: From<E>,
{
    #[instrument(skip(self, payload))]
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OTError> {
        let base_sender_setup = match self.stream.next().await {
            Some(Ok(Message::SenderSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderSetup");

        let base_setup = self.ot.base_setup(base_sender_setup.try_into().unwrap())?;

        trace!("Sending ReceiverSetup");
        self.stream.send(Message::ReceiverSetup(base_setup)).await?;

        let base_payload = match self.stream.next().await {
            Some(Ok(Message::SenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderPayload");

        self.ot.base_receive(base_payload.try_into().unwrap())?;

        let extension_receiver_setup = match self.stream.next().await {
            Some(Ok(Message::ExtReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received ExtReceiverSetup");

        self.ot
            .extension_setup(extension_receiver_setup.try_into().unwrap())?;
        let payload = self.ot.send(payload)?;

        self.stream.send(Message::ExtSenderPayload(payload)).await?;
        trace!("Sending ExtSenderPayload");

        Ok(())
    }
}
