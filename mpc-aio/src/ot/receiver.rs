use super::errors::OtError;
use crate::twopc::TwoPCProtocol;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{OtMessage, OtReceive};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;

pub struct OtReceiver<OT>
where
    OT: OtReceive + Send,
{
    ot: OT,
}

impl<OT: OtReceive + Send> OtReceiver<OT> {
    pub fn new(ot: OT) -> Self {
        Self { ot }
    }
}

#[async_trait]
impl<OT: OtReceive + Send> TwoPCProtocol<OtMessage> for OtReceiver<OT> {
    type Input = Vec<bool>;
    type Error = OtError;
    type Output = Vec<Block>;

    async fn run<
        S: Sink<OtMessage> + Stream<Item = Result<OtMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    >(
        &mut self,
        stream: &mut S,
        input: Self::Input,
    ) -> Result<Self::Output, Self::Error>
    where
        Self::Error: From<<S as Sink<OtMessage>>::Error>,
        Self::Error: From<E>,
    {
        let base_setup = self.ot.base_setup()?;

        stream.send(OtMessage::BaseSenderSetup(base_setup)).await?;

        let base_receiver_setup = match stream.next().await {
            Some(Ok(OtMessage::BaseReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let payload = self.ot.base_send(base_receiver_setup.try_into().unwrap())?;

        stream.send(OtMessage::BaseSenderPayload(payload)).await?;

        let setup = self.ot.extension_setup(input.as_slice())?;

        stream.send(OtMessage::ReceiverSetup(setup)).await?;

        let payload = match stream.next().await {
            Some(Ok(OtMessage::SenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let values = self
            .ot
            .receive(input.as_slice(), payload.try_into().unwrap())?;

        Ok(values)
    }
}
