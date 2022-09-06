use crate::ot::OTError;

use super::{ObliviousSend, ObliviousSetup};
use async_trait::async_trait;
use futures::{stream, Sink, SinkExt, Stream, StreamExt};
use mpc_core::{
    msgs::ot::ExtSenderPayload,
    msgs::ot::OTMessage,
    ot::extension::{s_state, Kos15Sender},
    Block,
};

#[async_trait]
impl ObliviousSend for Kos15Sender<s_state::RandSetup> {
    type Inputs = Vec<[Block; 2]>;
    type Envelope = ExtSenderPayload;
    type Message = OTMessage;

    async fn send(
        &mut self,
        stream: impl Stream<Item = Self::Message> + Unpin + Send,
        sink: impl Sink<Self::Message> + Unpin + Send,
        inputs: Self::Inputs,
    ) -> Box<dyn Stream<Item = Result<Self::Envelope, OTError>>> {
        let message = match stream.next().await {
            Some(OTMessage::ExtDerandomize(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };
        Box::new(
            stream::iter(inputs)
                .zip(stream::iter(message.flip))
                .map(|(input, flip)| self.rand_send(input, flip)),
        )
    }
}

#[async_trait]
impl ObliviousSetup for Kos15Sender {
    type Actor = Kos15Sender<s_state::RandSetup>;
    type Message = OTMessage;

    async fn setup(
        input: impl Stream<Item = OTMessage> + Unpin + Send,
        output: impl Sink<OTMessage> + Unpin + Send,
    ) -> Result<Self::Actor, OTError> {
        let kos_sender = Kos15Sender::default();
        let message = match input.next().await {
            Some(OTMessage::BaseSenderSetupWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };

        let (kos_sender, message) = kos_sender.base_setup(message)?;
        output
            .send(OTMessage::BaseReceiverSetupWrapper(message))
            .await;

        let message = match input.next().await {
            Some(OTMessage::BaseSenderPayloadWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };

        let kos_sender = kos_sender.base_receive(message)?;

        let message = match input.next().await {
            Some(OTMessage::ExtReceiverSetup(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };

        let kos_sender = kos_sender.rand_extension_setup(message)?;
        Ok(kos_sender)
    }
}
