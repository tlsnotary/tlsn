use super::{OTChannel, ObliviousReceive};
use crate::{OTError, ObliviousAcceptCommit, ObliviousVerify};
use aes::{cipher::NewBlockCipher, Aes128, BlockDecrypt};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::Block;
use mpc_ot_core::{
    extension::{r_state, Kos15Receiver},
    msgs::{ExtSenderEncryptedPayload, OTMessage},
    r_state::ReceiverState,
};
use utils_aio::{
    expect_msg_or_err,
    non_blocking_backend::{Backend, NonBlockingBackend},
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

    /// Set up the receiver for random OT
    ///
    /// * `count` - The number of OTs the receiver should prepare
    pub async fn rand_setup(
        mut self,
        count: usize,
    ) -> Result<Kos15IOReceiver<r_state::RandSetup>, OTError> {
        let (kos_receiver, message) =
            Backend::spawn(move || self.inner.base_setup().map_err(OTError::from)).await?;
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

        let (kos_receiver, message) = Backend::spawn(move || {
            kos_receiver
                .rand_extension_setup(count)
                .map_err(OTError::from)
        })
        .await?;

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

// The idea for obliviously receiving a vec of Blocks is for the sender to send an AES encryption key
// using OT, which can then later be used by the receiver to decrypt an arbitrary long message, which
// is sent shortly after the OT. This way we extend our OT from 128-bit maximum message length to an
// unlimited message length.
#[async_trait]
impl<const N: usize> ObliviousReceive<bool, [Block; N]> for Kos15IOReceiver<r_state::RandSetup> {
    async fn receive(&mut self, choices: Vec<bool>) -> Result<Vec<[Block; N]>, OTError> {
        // Receive AES encryption keys from OT
        let keys = ObliviousReceive::<bool, Block>::receive(self, choices.clone()).await?;

        // Expect the sender to send the encrypted messages
        let ExtSenderEncryptedPayload { ciphertexts } = expect_msg_or_err!(
            self.channel.next().await,
            OTMessage::ExtSenderEncryptedPayload,
            OTError::Unexpected
        )?;

        // Check that the Sender sent the correct number of ciphertexts
        let expected_len = choices.len() * 2 * N * Block::LEN;
        if ciphertexts.len() != expected_len {
            return Err(OTError::InvalidCiphertextLength(
                expected_len,
                ciphertexts.len(),
            ));
        }

        // Decrypt one of the ciphertexts from each pair with a corresponding key
        let mut plaintext: Vec<[Block; N]> = Vec::with_capacity(choices.len());
        for ((key, choice), msgs) in keys
            .iter()
            .zip(choices.into_iter())
            .zip(ciphertexts.chunks_exact(2 * N * Block::LEN))
        {
            let cipher = Aes128::new(&key.to_be_bytes().into());

            // The ciphertexts are sent flattened as [msg_0, msg_1]
            // We select the correct slice based on the choice bit
            let msg_slice = if choice {
                // msg_1
                &msgs[N * Block::LEN..2 * N * Block::LEN]
            } else {
                // msg_0
                &msgs[0..N * Block::LEN]
            };

            // Convert the slice into an array of [u8; Block::LEN]
            let msg: [[u8; Block::LEN]; N] = std::array::from_fn(|i| {
                msg_slice[i * Block::LEN..(i + 1) * Block::LEN]
                    .try_into()
                    .expect(&format!("Expected array to have length {}", Block::LEN))
            });

            // Convert the array of [u8; Block::LEN] into an array of generic_array
            let mut msg: [_; N] = std::array::from_fn(|i| msg[i].into());

            // Decrypt
            cipher.decrypt_blocks(&mut msg);

            // Convert the array of generic_array into an array of blocks
            let msg: [Block; N] = std::array::from_fn(|i| msg[i].into());

            plaintext.push(msg);
        }

        Ok(plaintext)
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
