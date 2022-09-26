use super::{OTChannel, ObliviousReceive};
use crate::protocol::ot::{OTError, ObliviousVerify};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::{
    msgs::ot::{ExtSenderCommit, ExtSenderDecommit, OTMessage},
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
        mut self,
        choice_len: usize,
    ) -> Result<Kos15IOReceiver<r_state::RandSetup>, OTError> {
        let (kos_receiver, message) = self.inner.base_setup()?;
        self.channel
            .send(OTMessage::BaseSenderSetupWrapper(message))
            .await?;

        let message = match self.channel.next().await {
            Some(OTMessage::BaseReceiverSetupWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => {
                return Err(OTError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (kos_receiver, message) = kos_receiver.base_send(message)?;
        self.channel
            .send(OTMessage::BaseSenderPayloadWrapper(message))
            .await?;

        let (kos_receiver, message) = kos_receiver.rand_extension_setup(choice_len)?;

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

        let message = match self.channel.next().await {
            Some(OTMessage::ExtSenderPayload(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => {
                return Err(OTError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };
        let out = self.inner.rand_receive(&message)?;
        Ok(out)
    }
}

#[async_trait]
impl ObliviousVerify for Kos15IOReceiver<r_state::RandSetup> {
    type Commitment = ExtSenderCommit;
    type Decommitment = ExtSenderDecommit;
    async fn verify(
        mut self,
        commit: Self::Commitment,
        decommit: Self::Decommitment,
    ) -> Result<(), OTError> {
        self.inner
            .verify(commit, decommit)
            .map_err(OTError::CommittedOT)
    }
}
