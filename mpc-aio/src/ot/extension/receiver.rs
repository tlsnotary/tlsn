use super::OTError;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use mpc_core::ot::{ExtReceiveCore, Message};
use mpc_core::proto::ot::Message as ProtoMessage;
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::{instrument, trace};
use utils_aio::codec::ProstCodecDelimited;

pub struct ExtReceiver<OT, S> {
    ot: OT,
    stream: Framed<S, ProstCodecDelimited<Message, ProtoMessage>>,
}

#[async_trait]
pub trait ExtOTReceive {
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError>;
}

impl<OT, S> ExtReceiver<OT, S>
where
    OT: ExtReceiveCore + Send,
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
impl<OT, S> ExtOTReceive for ExtReceiver<OT, S>
where
    OT: ExtReceiveCore + Send,
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    #[instrument(skip(self, choice))]
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError> {
        let base_setup = self.ot.base_setup()?;

        trace!("Sending BaseSenderSetup");
        self.stream
            .send(Message::BaseSenderSetup(base_setup))
            .await?;

        let base_receiver_setup = match self.stream.next().await {
            Some(Ok(Message::BaseReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received BaseReceiverSetup");

        let payload = self.ot.base_send(base_receiver_setup.try_into().unwrap())?;

        trace!("Sending BaseSenderPayload");
        self.stream
            .send(Message::BaseSenderPayload(payload))
            .await?;

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

        let values = self.ot.receive(payload.try_into().unwrap())?;

        Ok(values)
    }
}
