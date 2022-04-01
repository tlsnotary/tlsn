use super::errors::OtError;
use crate::twopc::TwoPCProtocol;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::ot::{OtMessage, OtSend};
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;

pub struct OtSender<OT>
where
    OT: OtSend + Send,
{
    ot: OT,
}

impl<OT: OtSend + Send> OtSender<OT> {
    pub fn new(ot: OT) -> Self {
        Self { ot }
    }
}

#[async_trait]
impl<OT: OtSend + Send> TwoPCProtocol<OtMessage> for OtSender<OT> {
    type Input = Vec<[Block; 2]>;
    type Error = OtError;
    type Output = ();

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
        let base_sender_setup = match stream.next().await {
            Some(Ok(OtMessage::BaseSenderSetup(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let base_setup = self.ot.base_setup(base_sender_setup.try_into().unwrap())?;

        stream
            .send(OtMessage::BaseReceiverSetup(base_setup))
            .await?;

        let base_payload = match stream.next().await {
            Some(Ok(OtMessage::BaseSenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        self.ot.base_receive(base_payload.try_into().unwrap())?;

        let extension_receiver_setup = match stream.next().await {
            Some(Ok(OtMessage::ReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OtError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        self.ot
            .extension_setup(extension_receiver_setup.try_into().unwrap())?;
        let payload = self.ot.send(&input)?;

        stream.send(OtMessage::SenderPayload(payload)).await?;

        Ok(())
    }
}
