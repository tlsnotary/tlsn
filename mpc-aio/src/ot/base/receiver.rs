use super::OTError;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use mpc_core::ot::{DhOtReceiver, Message};
use mpc_core::proto::ot::Message as ProtoMessage;
use mpc_core::Block;
use rand::thread_rng;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::{instrument, trace};
use utils_aio::codec::ProstCodecDelimited;

pub struct Receiver<S> {
    ot: DhOtReceiver,
    stream: Framed<S, ProstCodecDelimited<Message, ProtoMessage>>,
}

#[async_trait]
pub trait OTReceive {
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError>;
}

impl<S> Receiver<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self {
            ot: DhOtReceiver::default(),
            stream: Framed::new(
                stream,
                ProstCodecDelimited::<Message, ProtoMessage>::default(),
            ),
        }
    }
}

#[async_trait]
impl<S> OTReceive for Receiver<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    #[instrument(skip(self, choice))]
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError> {
        let setup = match self.stream.next().await {
            Some(Ok(Message::BaseSenderSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderSetup: {:?}", &setup);

        let setup = self.ot.setup(&mut thread_rng(), choice, setup)?;

        trace!("Sending ReceiverSetup: {:?}", &setup);
        self.stream.send(Message::BaseReceiverSetup(setup)).await?;

        let payload = match self.stream.next().await {
            Some(Ok(Message::BaseSenderPayload(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderPayload: {:?}", &payload);

        let values = self.ot.receive(payload)?;

        Ok(values)
    }
}
