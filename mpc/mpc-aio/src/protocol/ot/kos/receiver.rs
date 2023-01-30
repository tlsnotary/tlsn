use super::{OTChannel, ObliviousReceive};
use crate::protocol::ot::{OTError, ObliviousAcceptCommit, ObliviousVerify};
use aes::{
    cipher::{generic_array::GenericArray, NewBlockCipher},
    Aes128, BlockDecrypt,
};
use async_trait::async_trait;
use cipher::consts::U16;
use futures::{SinkExt, StreamExt};
use mpc_core::{
    msgs::ot::{ExtEncryptedData, OTMessage},
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

    /// Set up the receiver for random OT
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

impl Kos15IOReceiver<r_state::RandSetup> {
    /// Returns the number of remaining OTs which have not been consumed yet
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    /// Splits OT into separate instances, returning the original instance and the new instance
    /// respectively.
    ///
    /// * channel - Channel to attach to the new instance
    /// * count - Number of OTs to allocate to the new instance
    pub fn split(self, channel: OTChannel, split_at: usize) -> Result<(Self, Self), OTError> {
        let Self {
            inner: mut child,
            channel: parent_channel,
        } = self;

        let parent = Self {
            inner: child.split(split_at)?,
            channel: parent_channel,
        };

        let child = Self {
            inner: child,
            channel,
        };

        Ok((parent, child))
    }
}

#[async_trait]
impl ObliviousReceive<bool, Block> for Kos15IOReceiver<r_state::RandSetup> {
    async fn receive(&mut self, choices: Vec<bool>) -> Result<Vec<Block>, OTError> {
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
impl ObliviousReceive<bool, Vec<Block>> for Kos15IOReceiver<r_state::RandSetup> {
    async fn receive(&mut self, choices: Vec<bool>) -> Result<Vec<Vec<Block>>, OTError> {
        // Get keys from OT
        let keys = ObliviousReceive::<bool, Block>::receive(self, choices.clone()).await?;

        // Get ciphertexts
        let ExtEncryptedData { mut ciphertexts } = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::ExtEncryptedData,
            OTError::Unexpected
        )?;

        //Decrypt ciphertexts with keys
        let mut out: Vec<Vec<Block>> = Vec::with_capacity(choices.len());
        for k in 0..choices.len() {
            let mut blocks: Vec<GenericArray<u8, U16>> = ciphertexts[k][choices[k] as usize]
                .iter_mut()
                .map(|block| GenericArray::clone_from_slice(&block.inner().to_be_bytes()))
                .collect();

            let cipher = Aes128::new(&keys[k].inner().to_be_bytes().into());
            cipher.decrypt_blocks(&mut blocks);

            out.push(
                blocks
                    .iter()
                    .map(|gen_arr| {
                        let arr: [u8; 16] = gen_arr
                            .as_slice()
                            .try_into()
                            .expect("Expected array to have length 16");
                        Block::from(arr)
                    })
                    .collect(),
            )
        }
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
impl ObliviousVerify<[Block; 2]> for Kos15IOReceiver<r_state::RandSetup> {
    async fn verify(mut self, input: Vec<[Block; 2]>) -> Result<(), OTError> {
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
