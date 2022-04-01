use super::errors::OtError;
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

    async fn receive<
        S: Sink<OtMessage> + Stream<Item = Result<OtMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    >(
        &mut self,
        stream: &mut S,
        choice: &[bool],
    ) -> Result<Vec<Block>, OtError>
    where
        OtError: From<<S as Sink<OtMessage>>::Error>,
        OtError: From<E>,
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

        let setup = self.ot.extension_setup(choice)?;

        stream.send(OtMessage::ReceiverSetup(setup)).await?;

        let payload = match stream.next().await {
            Some(Ok(OtMessage::SenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let values = self.ot.receive(choice, payload.try_into().unwrap())?;

        Ok(values)
    }
}
