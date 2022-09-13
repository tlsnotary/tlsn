use super::{ObliviousSend, Protocol};
use crate::protocol::ot::{OTChannel, OTError, ObliviousTransfer};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::{
    msgs::ot::{ExtReceiverSetup, OTMessage},
    ot::{
        extension::{s_state, Kos15Sender},
        s_state::SenderState,
    },
    Block,
};

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
        self,
    ) -> Result<Kos15IOSender<s_state::Setup>, <ObliviousTransfer as Protocol>::Error> {
        let (kos_io_sender, message) = self.setup_from().await?;
        let kos_sender = kos_io_sender.inner.extension_setup(message)?;
        let kos_io_sender = Kos15IOSender {
            inner: kos_sender,
            channel: kos_io_sender.channel,
        };
        Ok(kos_io_sender)
    }

    pub async fn rand_setup(
        self,
    ) -> Result<Kos15IOSender<s_state::RandSetup>, <ObliviousTransfer as Protocol>::Error> {
        let (kos_io_sender, message) = self.setup_from().await?;
        let kos_sender = kos_io_sender.inner.rand_extension_setup(message)?;
        let kos_io_sender = Kos15IOSender {
            inner: kos_sender,
            channel: kos_io_sender.channel,
        };
        Ok(kos_io_sender)
    }

    async fn setup_from(
        mut self,
    ) -> Result<
        (Kos15IOSender<s_state::BaseReceive>, ExtReceiverSetup),
        <ObliviousTransfer as Protocol>::Error,
    > {
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

        Ok((
            Kos15IOSender {
                inner: kos_sender,
                channel: self.channel,
            },
            message,
        ))
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

#[async_trait]
impl ObliviousSend for Kos15IOSender<s_state::RandSetup> {
    type Inputs = Vec<[Block; 2]>;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError> {
        let message = match self.channel.next().await {
            Some(OTMessage::ExtDerandomize(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => return Err(OTError::IOError),
        };
        let message = self.inner.rand_send(&inputs, message)?;
        self.channel
            .send(OTMessage::ExtSenderPayload(message))
            .await?;
        Ok(())
    }
}
