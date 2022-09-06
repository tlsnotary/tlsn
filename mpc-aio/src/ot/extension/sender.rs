use crate::ot::OTError;

use super::{ObliviousSend, ObliviousSetup};
use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::{
    msgs::ot::{ExtDerandomize, OTMessage},
    ot::extension::{s_state, Kos15Sender},
    Block,
};

#[async_trait]
impl ObliviousSend for Kos15Sender<s_state::RandSetup> {
    type Inputs = Vec<[Block; 2]>;
    type Envelope = Vec<[Block; 2]>;
    type Message = ExtDerandomize;

    async fn send(
        &mut self,
        stream: impl Stream<Item = Self::Message> + Unpin + Send,
        inputs: Self::Inputs,
    ) -> Box<dyn Stream<Item = Result<Self::Envelope, OTError>>> {
        Box::new(stream.map(|message| {
            self.rand_send(&inputs, message)
                .map(|payload| payload.ciphertexts)
                .map_err(OTError::from)
        }))
    }
}

#[async_trait]
impl ObliviousSetup for Kos15Sender {
    type Actor = Kos15Sender<s_state::RandSetup>;
    type Message = OTMessage;

    async fn setup(
        stream: impl Stream<Item = OTMessage> + Unpin + Send,
        sink: impl Sink<OTMessage> + Unpin + Send,
    ) -> Result<Self::Actor, OTError> {
        let kos_sender = Kos15Sender::default();
        let message = match stream.next().await {
            Some(OTMessage::BaseSenderSetupWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };

        let (kos_sender, message) = kos_sender.base_setup(message)?;
        sink.send(OTMessage::BaseReceiverSetupWrapper(message))
            .await;

        let message = match stream.next().await {
            Some(OTMessage::BaseSenderPayloadWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };

        let kos_sender = kos_sender.base_receive(message)?;

        let message = match stream.next().await {
            Some(OTMessage::ExtReceiverSetup(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };

        let kos_sender = kos_sender.rand_extension_setup(message)?;
        Ok(kos_sender)
    }
}
