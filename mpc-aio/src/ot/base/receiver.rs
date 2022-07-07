use super::OTError;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use mpc_core::ot::{Message, ReceiveCore};
use mpc_core::proto::ot::Message as ProtoMessage;
use mpc_core::Block;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::{instrument, trace};
use utils_aio::codec::ProstCodecDelimited;

pub struct Receiver<OT, S> {
    ot: OT,
    stream: Framed<S, ProstCodecDelimited<Message, ProtoMessage>>,
}

#[async_trait]
pub trait OTReceive {
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError>;
}

impl<OT, S> Receiver<OT, S>
where
    OT: ReceiveCore + Send,
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
impl<OT, S> OTReceive for Receiver<OT, S>
where
    OT: ReceiveCore + Send,
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    #[instrument(skip(self, choice))]
    async fn receive(&mut self, choice: &[bool]) -> Result<Vec<Block>, OTError> {
        let setup = match self.stream.next().await {
            Some(Ok(Message::SenderSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderSetup: {:?}", &setup);

        let setup = self.ot.setup(choice, setup)?;

        trace!("Sending ReceiverSetup: {:?}", &setup);
        self.stream.send(Message::ReceiverSetup(setup)).await?;

        let payload = match self.stream.next().await {
            Some(Ok(Message::SenderOutput(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received SenderPayload: {:?}", &payload);

        let values = self.ot.receive(payload)?;

        Ok(values)
    }
}
