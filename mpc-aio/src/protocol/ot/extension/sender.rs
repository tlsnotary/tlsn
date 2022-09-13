use super::{Channel, ObliviousSend, Protocol};
use crate::protocol::ot::OTError;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::{
    msgs::ot::OTMessage,
    ot::{
        extension::{s_state, Kos15Sender},
        s_state::SenderState,
    },
    Block,
};
use std::pin::Pin;

impl<T: SenderState> Protocol for Kos15Sender<T> {
    type Message = OTMessage;
    type Error = OTError;
}

type OTChannel = Pin<
    Box<dyn Channel<<Kos15Sender as Protocol>::Message, Error = <Kos15Sender as Protocol>::Error>>,
>;

pub struct Kos15IOSender<T: SenderState> {
    inner: Kos15Sender<T>,
    channel: OTChannel,
}

impl Kos15IOSender<s_state::Initialized> {
    pub fn new(channel: OTChannel) -> Self {
        Self {
            inner: Kos15Sender::default(),
            channel,
        }
    }

    pub async fn setup(
        mut self,
    ) -> Result<Kos15IOSender<s_state::Setup>, <Kos15Sender as Protocol>::Error> {
        let message = match self.channel.next().await {
            Some(OTMessage::BaseSenderSetupWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError),
        };

        let (kos_sender, message) = self.inner.base_setup(message)?;
        self.channel
            .send(OTMessage::BaseReceiverSetupWrapper(message))
            .await?;

        let message = match self.channel.next().await {
            Some(OTMessage::BaseSenderPayloadWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError),
        };

        let kos_sender = kos_sender.base_receive(message)?;

        let message = match self.channel.next().await {
            Some(OTMessage::ExtReceiverSetup(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError),
        };

        let kos_sender = kos_sender.extension_setup(message)?;

        Ok(Kos15IOSender {
            inner: kos_sender,
            channel: self.channel,
        })
    }
}

#[async_trait]
impl ObliviousSend for Kos15IOSender<s_state::Setup> {
    type Inputs = Vec<[Block; 2]>;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError> {
        let message = self.inner.send(&inputs)?;
        self.channel
            .send(OTMessage::ExtSenderPayload(message))
            .await?;
        Ok(())
    }
}
