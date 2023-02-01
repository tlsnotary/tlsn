use super::{OTChannel, ObliviousSend};
use crate::protocol::ot::{OTError, ObliviousCommit, ObliviousReveal};
use aes::{
    cipher::{generic_array::GenericArray, NewBlockCipher},
    Aes128, BlockEncrypt,
};
use async_trait::async_trait;
use cipher::consts::U16;
use futures::{SinkExt, StreamExt};
use mpc_core::{
    msgs::ot::{ExtSenderEncryptedPayload, OTMessage},
    ot::{
        extension::{s_state, Kos15Sender},
        s_state::SenderState,
    },
    Block,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
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

    /// Set up the sender for random OT
    ///
    /// * `count` - The number of OTs the sender should prepare
    pub async fn rand_setup(
        mut self,
        count: usize,
    ) -> Result<Kos15IOSender<s_state::RandSetup>, OTError> {
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

        let kos_sender = kos_sender.rand_extension_setup(count, message)?;
        let kos_io_sender = Kos15IOSender {
            inner: kos_sender,
            channel: self.channel,
            barrier: self.barrier,
        };
        Ok(kos_io_sender)
    }
}

impl Kos15IOSender<s_state::RandSetup> {
    /// Returns the number of remaining OTs which have not been consumed yet
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    /// Splits OT into separate instances, returning the original instance and the new instance
    /// respectively.
    ///
    /// * channel - Channel to attach to the new instance
    /// * count - Number of OTs to allocate to the new instance
    pub fn split(self, channel: OTChannel, count: usize) -> Result<(Self, Self), OTError> {
        let Self {
            inner: mut child,
            channel: parent_channel,
            barrier,
        } = self;

        let parent = Self {
            inner: child.split(count)?,
            channel: parent_channel,
            barrier: barrier.clone(),
        };

        let child = Self {
            inner: child,
            channel,
            barrier,
        };

        Ok((parent, child))
    }
}

#[async_trait]
impl ObliviousSend<[Block; 2]> for Kos15IOSender<s_state::RandSetup> {
    async fn send(&mut self, inputs: Vec<[Block; 2]>) -> Result<(), OTError> {
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

// The idea is to send AES encryption keys in the OT, which can then later be used by the receiver
// to decrypt arbitrary long messages, which are sent shortly after the OT. This way we extend our
// OT from 128-bit maximum message length to an unlimited message length
#[async_trait]
impl ObliviousSend<[Vec<Block>; 2]> for Kos15IOSender<s_state::RandSetup> {
    async fn send(&mut self, inputs: Vec<[Vec<Block>; 2]>) -> Result<(), OTError> {
        let mut rng = ChaCha20Rng::from_entropy();

        // Prepare keys and convert inputs
        let mut keys: Vec<[Block; 2]> = Vec::with_capacity(inputs.len());
        let mut inputs: Vec<[Vec<GenericArray<u8, U16>>; 2]> = inputs
            .iter()
            .map(|blocks| {
                [
                    blocks[0]
                        .iter()
                        .map(|block| GenericArray::clone_from_slice(&block.inner().to_be_bytes()))
                        .collect(),
                    blocks[1]
                        .iter()
                        .map(|block| GenericArray::clone_from_slice(&block.inner().to_be_bytes()))
                        .collect(),
                ]
            })
            .collect();

        // Encrypt inputs and collect keys
        for k in 0..inputs.len() {
            let (key1, key2) = (Block::random(&mut rng), Block::random(&mut rng));
            let (cipher1, cipher2) = (
                Aes128::new(&key1.inner().to_be_bytes().into()),
                Aes128::new(&key2.inner().to_be_bytes().into()),
            );
            cipher1.encrypt_blocks(&mut inputs[k][0]);
            cipher2.encrypt_blocks(&mut inputs[k][1]);
            keys.push([key1, key2]);
        }

        // Send keys in OT
        ObliviousSend::<[Block; 2]>::send(self, keys).await?;

        // Convert input back to blocks
        let ciphertexts: Vec<[Vec<Block>; 2]> = inputs
            .iter()
            .map(|blocks| {
                [
                    blocks[0]
                        .iter()
                        .map(|gen_arr| {
                            let arr: [u8; 16] = gen_arr
                                .as_slice()
                                .try_into()
                                .expect("Expected array to have length 16");
                            Block::from(arr)
                        })
                        .collect(),
                    blocks[1]
                        .iter()
                        .map(|gen_arr| {
                            let arr: [u8; 16] = gen_arr
                                .as_slice()
                                .try_into()
                                .expect("Expected array to have length 16");
                            Block::from(arr)
                        })
                        .collect(),
                ]
            })
            .collect();

        // Send ciphertexts now
        self.channel
            .send(OTMessage::ExtSenderEncryptedPayload(
                ExtSenderEncryptedPayload { ciphertexts },
            ))
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
        // wait for all other split-off OTs (if any) to also call reveal()
        self.barrier.wait().await;
        let message = unsafe { self.inner.reveal()? };
        self.channel
            .send(OTMessage::ExtSenderReveal(message))
            .await?;
        Ok(())
    }
}
