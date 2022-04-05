use super::OTError;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{Message, ReceiveCore};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tracing::{instrument, trace};

pub struct Receiver<OT, S> {
    ot: OT,
    stream: S,
}

#[async_trait]
pub trait OTReceive {
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError>;
}

impl<
        OT: ReceiveCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > Receiver<OT, S>
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
        OT: ReceiveCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > OTReceive for Receiver<OT, S>
where
    OTError: From<<S as Sink<Message>>::Error>,
    OTError: From<E>,
{
    #[instrument(skip(self, choice))]
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError> {
        let setup = match self.stream.next().await {
            Some(Ok(Message::SenderSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderSetup");

        let setup = self.ot.setup(choice, setup)?;

        trace!("Sending ReceiverSetup");
        self.stream.send(Message::ReceiverSetup(setup)).await?;

        let payload = match self.stream.next().await {
            Some(Ok(Message::SenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderPayload");

        let values = self.ot.receive(payload)?;

        Ok(values)
    }
}
