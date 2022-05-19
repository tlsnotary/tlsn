use super::OTError;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use mpc_core::ot::{ExtSendCore, Message};
use mpc_core::proto::ot::Message as ProtoMessage;
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::{instrument, trace};
use utils_aio::codec::ProstCodecDelimited;

pub struct ExtSender<OT, S> {
    ot: OT,
    stream: Framed<S, ProstCodecDelimited<Message, ProtoMessage>>,
}

#[async_trait]
pub trait ExtOTSend {
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OTError>;
}

impl<OT, S> ExtSender<OT, S>
where
    OT: ExtSendCore + Send,
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    pub fn new(ot: OT, stream: S) -> Self {
        Self {
            ot,
            stream: Framed::new(
                stream,
                ProstCodecDelimited::<Message, ProtoMessage>::default(),
            ),
        }
    }
}

#[async_trait]
impl<OT, S> ExtOTSend for ExtSender<OT, S>
where
    OT: ExtSendCore + Send,
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    #[instrument(skip(self, payload))]
    async fn send(&mut self, payload: &[[Block; 2]]) -> Result<(), OTError> {
        let base_sender_setup = match self.stream.next().await {
            Some(Ok(Message::BaseSenderSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderSetup");

        let base_setup = self.ot.base_setup(base_sender_setup.try_into().unwrap())?;

        trace!("Sending ReceiverSetup");
        self.stream
            .send(Message::BaseReceiverSetup(base_setup))
            .await?;

        let base_payload = match self.stream.next().await {
            Some(Ok(Message::BaseSenderPayload(m))) => m,
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
