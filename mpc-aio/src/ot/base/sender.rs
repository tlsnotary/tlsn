use super::{OTError, ObliviousSend};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use mpc_core::ot::{DhOtSender, Message};
use mpc_core::proto::ot::Message as ProtoMessage;
use mpc_core::Block;
use rand::thread_rng;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tracing::{instrument, trace};
use utils_aio::codec::ProstCodecDelimited;

pub struct Sender<T: AsyncWrite + AsyncRead> {
    ot: DhOtSender,
    stream: Framed<T, ProstCodecDelimited<Message, ProtoMessage>>,
}

impl<T: AsyncWrite + AsyncRead> Sender<T> {
    pub fn new(stream: T) -> Self {
        Self {
            ot: DhOtSender::default(),
            stream: Framed::new(
                stream,
                ProstCodecDelimited::<Message, ProtoMessage>::default(),
            ),
        }
    }
}

#[async_trait]
impl<T> ObliviousSend for Sender<T>
where
    T: AsyncWrite + AsyncRead + Send + Unpin,
{
    type Payload = Vec<[Block; 2]>;

    #[instrument(skip(self, payload))]
    async fn send<T>(&mut self, payload: Payload, channel: T) -> Result<(), OTError> {
        let setup = self.ot.setup(&mut thread_rng())?;

        trace!("Sending SenderSetup: {:?}", &setup);
        self.stream.send(Message::BaseSenderSetup(setup)).await?;

        let setup = match self.stream.next().await {
            Some(Ok(Message::BaseReceiverSetup(m))) => m,
            Some(Ok(m)) => return Err(OTError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received ReceiverSetup: {:?}", &setup);

        let payload = self.ot.send(payload, setup)?;

        trace!("Sending SenderPayload: {:?}", &payload);
        self.stream
            .send(Message::BaseSenderPayload(payload))
            .await?;

        Ok(())
    }
}
