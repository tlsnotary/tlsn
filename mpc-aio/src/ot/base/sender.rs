use super::OTError;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{Message, SendCore};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tracing::{instrument, trace};

pub struct Sender<OT, S> {
    ot: OT,
    stream: S,
}

#[async_trait]
pub trait OTSend {
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OTError>;
}

impl<
        OT: SendCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > Sender<OT, S>
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
        OT: SendCore + Send,
        S: Sink<Message> + Stream<Item = Result<Message, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > OTSend for Sender<OT, S>
where
    OTError: From<<S as Sink<Message>>::Error>,
    OTError: From<E>,
{
    #[instrument(skip(self, payload))]
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OTError> {
        let setup = self.ot.setup();

        trace!("Sending SenderSetup: {:?}", &setup);
        self.stream.send(Message::SenderSetup(setup)).await?;

        let setup = match self.stream.next().await {
            Some(Ok(Message::ReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received ReceiverSetup: {:?}", &setup);

        let payload = self.ot.send(payload, setup)?;

        trace!("Sending SenderPayload: {:?}", &payload);
        self.stream.send(Message::SenderPayload(payload)).await?;

        Ok(())
    }
}
