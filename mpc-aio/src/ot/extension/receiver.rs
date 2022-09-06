use crate::ot::{ObliviousReceive, ObliviousSetup};

use super::OTError;
use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::msgs::ot::OTMessage;
use mpc_core::ot::{r_state, Kos15Receiver};
use mpc_core::Block;

#[async_trait]
impl ObliviousReceive for Kos15Receiver<r_state::RandSetup> {
    type Choices = Vec<bool>;

    type Outputs = Vec<Block>;

    async fn receive(
        &mut self,
        choices: impl Stream<Item = Self::Choices> + Unpin + Send,
        output: impl Sink<Self::Message> + Unpin + Send,
    ) -> Box<dyn Stream<Item = Result<Self::Outputs, OTError>>> {
        Box::new(choices.map(|el| self.derandomize(&el).map_err(OTError::from)))
    }
}

#[async_trait]
impl ObliviousSetup for Kos15Receiver {
    type Actor = Kos15Receiver<r_state::RandSetup>;
    type Message = OTMessage;

    async fn setup_sender(
        input: impl Stream<Item = Self::Message> + Unpin + Send,
        output: impl Sink<Self::Message> + Unpin + Send,
    ) -> Result<Self::Actor, OTError> {
        let kos_receiver = Kos15Receiver::default();
        let (kos_receiver, message) = kos_receiver.base_setup()?;

        output
            .send(OTMessage::BaseSenderSetupWrapper(message))
            .await;

        let message = match input.next().await {
            Some(OTMessage::BaseReceiverSetupWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError)?,
        };

        let (kos_receiver, message) = kos_receiver.base_send(message)?;
        output
            .send(OTMessage::BaseSenderPayloadWrapper(message))
            .await;

        let (kos_receiver, message) = kos_receiver.rand_extension_setup(1_000_000)?;
        output.send(OTMessage::ExtReceiverSetup(message)).await;
        Ok(kos_receiver)
    }
}
