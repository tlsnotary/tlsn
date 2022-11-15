use super::{OTChannel, ObliviousReceive};
use crate::protocol::ot::{OTError, ObliviousAcceptCommit, ObliviousVerify};
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
use utils_aio::expect_msg_or_err;

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

    /// Setup the receiver for random OT
    ///
    /// * `count` - The number of OTs the receiver should prepare
    pub async fn rand_setup(
        mut self,
        count: usize,
    ) -> Result<Kos15IOReceiver<r_state::RandSetup>, OTError> {
        let (kos_receiver, message) = self.inner.base_setup()?;
        self.channel
            .send(OTMessage::BaseSenderSetupWrapper(message))
            .await?;
        let message = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::BaseReceiverSetupWrapper,
            OTError::Unexpected
        )?;

        let (kos_receiver, message) = kos_receiver.base_send(message)?;
        self.channel
            .send(OTMessage::BaseSenderPayloadWrapper(message))
            .await?;

        let (kos_receiver, message) = kos_receiver.rand_extension_setup(count)?;

        self.channel
            .send(OTMessage::ExtReceiverSetup(message))
            .await?;

        let kos_io_receiver = Kos15IOReceiver {
            inner: kos_receiver,
            channel: self.channel,
        };
        Ok(kos_io_receiver)
    }
}

#[async_trait]
impl ObliviousReceive for Kos15IOReceiver<r_state::RandSetup> {
    type Choice = bool;
    type Outputs = Vec<Block>;

    async fn receive(&mut self, choices: &[bool]) -> Result<Self::Outputs, OTError> {
        let message = self.inner.derandomize(&choices)?;
        self.channel
            .send(OTMessage::ExtDerandomize(message))
            .await?;

        let message = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::ExtSenderPayload,
            OTError::Unexpected
        )?;
        let out = self.inner.receive(message)?;
        Ok(out)
    }
}

#[async_trait]
impl ObliviousAcceptCommit for Kos15IOReceiver<r_state::Initialized> {
    async fn accept_commit(&mut self) -> Result<(), OTError> {
        let message = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::ExtSenderCommit,
            OTError::Unexpected
        )?;
        self.inner.store_commitment(message.0);
        Ok(())
    }
}

#[async_trait]
impl ObliviousVerify for Kos15IOReceiver<r_state::RandSetup> {
    type Input = [Block; 2];

    async fn verify(mut self, input: Vec<Self::Input>) -> Result<(), OTError> {
        let reveal = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::ExtSenderReveal,
            OTError::Unexpected
        )?;
        self.inner
            .verify(reveal, &input)
            .map_err(OTError::CommittedOT)
    }
}
