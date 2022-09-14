use super::{OTChannel, ObliviousReceive, ObliviousTransfer, Protocol};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::{
    msgs::ot::OTMessage,
    ot::{
        extension::{r_state, Kos15Receiver},
        r_state::ReceiverState,
    },
    Block,
};

pub struct Kos15IOReceiver<T: ReceiverState> {
    inner: Kos15Receiver<T>,
    channel: OTChannel,
}

impl Kos15IOReceiver<r_state::Initialized> {
    pub fn new(channel: OTChannel) -> Self {
        Self {
            inner: Kos15Receiver::default(),
            channel,
        }
    }

    pub async fn rand_setup(
        self,
        choice_len: usize,
    ) -> Result<Kos15IOReceiver<r_state::RandSetup>, <ObliviousTransfer as Protocol>::Error> {
        let mut kos_io_receiver = self.setup_from().await?;
        let (kos_receiver, message) = kos_io_receiver.inner.rand_extension_setup(choice_len)?;

        kos_io_receiver
            .channel
            .send(OTMessage::ExtReceiverSetup(message))
            .await?;

        let kos_io_receiver = Kos15IOReceiver {
            inner: kos_receiver,
            channel: kos_io_receiver.channel,
        };
        Ok(kos_io_receiver)
    }

    pub async fn setup(
        self,
        choices: &[bool],
    ) -> Result<Kos15IOReceiver<r_state::Setup>, <ObliviousTransfer as Protocol>::Error> {
        let mut kos_io_receiver = self.setup_from().await?;
        let (kos_receiver, message) = kos_io_receiver.inner.extension_setup(choices)?;

        kos_io_receiver
            .channel
            .send(OTMessage::ExtReceiverSetup(message))
            .await?;

        let kos_io_receiver = Kos15IOReceiver {
            inner: kos_receiver,
            channel: kos_io_receiver.channel,
        };
        Ok(kos_io_receiver)
    }

    async fn setup_from(
        mut self,
    ) -> Result<Kos15IOReceiver<r_state::BaseSend>, <ObliviousTransfer as Protocol>::Error> {
        let (kos_receiver, message) = self.inner.base_setup()?;
        self.channel
            .send(OTMessage::BaseSenderSetupWrapper(message))
            .await?;

        let message = match self.channel.next().await {
            Some(OTMessage::BaseReceiverSetupWrapper(m)) => m,
            Some(m) => return Err(<ObliviousTransfer as Protocol>::Error::Unexpected(m)),
            None => return Err(<ObliviousTransfer as Protocol>::Error::IOError),
        };

        let (kos_receiver, message) = kos_receiver.base_send(message)?;
        self.channel
            .send(OTMessage::BaseSenderPayloadWrapper(message))
            .await?;

        Ok(Kos15IOReceiver {
            inner: kos_receiver,
            channel: self.channel,
        })
    }
}

#[async_trait]
impl ObliviousReceive for Kos15IOReceiver<r_state::Setup> {
    type Choices = ();
    type Outputs = Vec<Block>;

    async fn receive(
        &mut self,
        _: Self::Choices,
    ) -> Result<Self::Outputs, <ObliviousTransfer as Protocol>::Error> {
        let message = match self.channel.next().await {
            Some(OTMessage::ExtSenderPayload(m)) => m,
            Some(m) => return Err(<ObliviousTransfer as Protocol>::Error::Unexpected(m)),
            None => return Err(<ObliviousTransfer as Protocol>::Error::IOError),
        };
        let out = self.inner.receive(message)?;
        Ok(out)
    }
}

#[async_trait]
impl ObliviousReceive for Kos15IOReceiver<r_state::RandSetup> {
    type Choices = Vec<bool>;
    type Outputs = Vec<Block>;

    async fn receive(
        &mut self,
        choices: Vec<bool>,
    ) -> Result<Self::Outputs, <ObliviousTransfer as Protocol>::Error> {
        let message = self.inner.derandomize(&choices)?;
        self.channel
            .send(OTMessage::ExtDerandomize(message))
            .await?;

        let message = match self.channel.next().await {
            Some(OTMessage::ExtSenderPayload(m)) => m,
            Some(m) => return Err(<ObliviousTransfer as Protocol>::Error::Unexpected(m)),
            None => return Err(<ObliviousTransfer as Protocol>::Error::IOError),
        };
        let out = self.inner.rand_receive(message)?;
        Ok(out)
    }
}
