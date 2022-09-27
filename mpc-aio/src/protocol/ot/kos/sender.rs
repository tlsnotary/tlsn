use super::{OTChannel, ObliviousSend};
use crate::protocol::ot::{OTError, ObliviousCommit, ObliviousDecommit};
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

    pub async fn rand_setup(mut self) -> Result<Kos15IOSender<s_state::RandSetup>, OTError> {
        let message = match self.channel.next().await {
            Some(OTMessage::BaseSenderSetupWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => {
                return Err(OTError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (kos_sender, message) = self.inner.base_setup(message)?;
        self.channel
            .send(OTMessage::BaseReceiverSetupWrapper(message))
            .await?;

        let message = match self.channel.next().await {
            Some(OTMessage::BaseSenderPayloadWrapper(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => {
                return Err(OTError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let kos_sender = kos_sender.base_receive(message)?;

        let message = match self.channel.next().await {
            Some(OTMessage::ExtReceiverSetup(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => {
                return Err(OTError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let kos_sender = kos_sender.rand_extension_setup(message)?;
        let kos_io_sender = Kos15IOSender {
            inner: kos_sender,
            channel: self.channel,
        };
        Ok(kos_io_sender)
    }
}

#[async_trait]
impl ObliviousSend for Kos15IOSender<s_state::RandSetup> {
    type Inputs = Vec<[Block; 2]>;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError> {
        let message = match self.channel.next().await {
            Some(OTMessage::ExtDerandomize(m)) => m,
            Some(m) => return Err(OTError::Unexpected(m)),
            None => {
                return Err(OTError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };
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
impl ObliviousDecommit for Kos15IOSender<s_state::RandSetup> {
    async fn decommit(mut self) -> Result<(), OTError> {
        let message = self.inner.decommit()?;
        self.channel
            .send(OTMessage::ExtSenderDecommit(message))
            .await?;
        Ok(())
    }
}
