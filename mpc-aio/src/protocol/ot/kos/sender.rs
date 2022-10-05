use super::{OTChannel, ObliviousSend};
use crate::protocol::ot::{OTError, ObliviousCommit, ObliviousReveal};
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
use utils_aio::{adaptive_barrier::AdaptiveBarrier, expect_msg_or_err};

pub struct Kos15IOSender<T: SenderState> {
    inner: Kos15Sender<T>,
    channel: OTChannel,
    // Needed for task synchronization for committed OT
    barrier: AdaptiveBarrier,
}

impl Kos15IOSender<s_state::Initialized> {
    pub fn new(channel: OTChannel) -> Self {
        Self {
            inner: Kos15Sender::default(),
            channel,
            barrier: AdaptiveBarrier::new(),
        }
    }

    pub async fn rand_setup(mut self) -> Result<Kos15IOSender<s_state::RandSetup>, OTError> {
        let message = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::BaseSenderSetupWrapper,
            OTError::Unexpected
        )?;

        let (kos_sender, message) = self.inner.base_setup(message)?;
        self.channel
            .send(OTMessage::BaseReceiverSetupWrapper(message))
            .await?;

        let message = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::BaseSenderPayloadWrapper,
            OTError::Unexpected
        )?;

        let kos_sender = kos_sender.base_receive(message)?;

        let message = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::ExtReceiverSetup,
            OTError::Unexpected
        )?;

        let kos_sender = kos_sender.rand_extension_setup(message)?;
        let kos_io_sender = Kos15IOSender {
            inner: kos_sender,
            channel: self.channel,
            barrier: self.barrier,
        };
        Ok(kos_io_sender)
    }
}

impl Kos15IOSender<s_state::RandSetup> {
    pub fn split(&mut self, channel: OTChannel, split_at: usize) -> Result<Self, OTError> {
        let new_ot = self.inner.split(split_at)?;
        Ok(Self {
            inner: new_ot,
            channel,
            barrier: self.barrier.clone(),
        })
    }
}

#[async_trait]
impl ObliviousSend for Kos15IOSender<s_state::RandSetup> {
    type Inputs = Vec<[Block; 2]>;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError> {
        let message = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::ExtDerandomize,
            OTError::Unexpected
        )?;
        let message = self.inner.rand_send(&inputs, message)?;
        self.channel
            .send(OTMessage::ExtSenderPayload(message))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ObliviousCommit for Kos15IOSender<s_state::Initialized> {
    async fn commit(&mut self) -> Result<(), OTError> {
        let message = self.inner.commit_to_seed();
        self.channel
            .send(OTMessage::ExtSenderCommit(message))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ObliviousReveal for Kos15IOSender<s_state::RandSetup> {
    async fn reveal(mut self) -> Result<(), OTError> {
        self.barrier.wait().await;
        let message = unsafe { self.inner.reveal()? };
        self.channel
            .send(OTMessage::ExtSenderReveal(message))
            .await?;
        Ok(())
    }
}
