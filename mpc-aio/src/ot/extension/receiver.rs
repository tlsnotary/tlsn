use super::OTError;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{ExtReceiveCore, Message};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tracing::{instrument, trace};

pub struct ExtReceiver<OT, S> {
    ot: OT,
    stream: S,
}

#[async_trait]
pub trait ExtOTReceive {
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError>;
}

impl<
        OT: ExtReceiveCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > ExtReceiver<OT, S>
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
        OT: ExtReceiveCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > ExtOTReceive for ExtReceiver<OT, S>
where
    OTError: From<<S as Sink<Message>>::Error>,
    OTError: From<E>,
{
    #[instrument(skip(self, choice))]
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError> {
        let base_setup = self.ot.base_setup()?;

        trace!("Sending SenderSetup");
        self.stream.send(Message::SenderSetup(base_setup)).await?;

        let base_receiver_setup = match self.stream.next().await {
            Some(Ok(Message::ReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received ReceiverSetup");

        let payload = self.ot.base_send(base_receiver_setup.try_into().unwrap())?;

        trace!("Sending SenderPayload");
        self.stream.send(Message::SenderPayload(payload)).await?;

        let setup = self.ot.extension_setup(choice)?;

        trace!("Sending ExtReceiverSetup");
        self.stream.send(Message::ExtReceiverSetup(setup)).await?;

        let payload = match self.stream.next().await {
            Some(Ok(Message::ExtSenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received ExtSenderPayload");

        let values = self.ot.receive(choice, payload.try_into().unwrap())?;

        Ok(values)
    }
}
