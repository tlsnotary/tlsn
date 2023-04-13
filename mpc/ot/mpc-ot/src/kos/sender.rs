use super::{OTChannel, ObliviousSendOwned};
use crate::{OTError, ObliviousCommitOwned, ObliviousRevealOwned};
use aes::{cipher::NewBlockCipher, Aes128, BlockEncrypt};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_core::Block;
use mpc_ot_core::{
    extension::{s_state, Kos15Sender},
    msgs::{ExtSenderEncryptedPayload, OTMessage},
    s_state::SenderState,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use utils_aio::{
    expect_msg_or_err,
    non_blocking_backend::{Backend, NonBlockingBackend},
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

        let (kos_sender, message) =
            Backend::spawn(move || self.inner.base_setup(message).map_err(OTError::from)).await?;
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

        let kos_sender = Backend::spawn(move || {
            kos_sender
                .rand_extension_setup(count, message)
                .map_err(OTError::from)
        })
        .await?;
        let kos_io_sender = Kos15IOSender {
            inner: kos_sender,
            channel: self.channel,
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
        } = self;

        let parent = Self {
            inner: child.split(count)?,
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
impl ObliviousSendOwned<[Block; 2]> for Kos15IOSender<s_state::RandSetup> {
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

// The idea for obliviously receiving a vec of Blocks is for the sender to send an AES encryption key
// using OT, which can then later be used by the receiver to decrypt an arbitrary long message, which
// is sent shortly after the OT. This way we extend our OT from 128-bit maximum message length to an
// unlimited message length.
#[async_trait]
impl<const N: usize> ObliviousSendOwned<[[Block; N]; 2]> for Kos15IOSender<s_state::RandSetup> {
    async fn send(&mut self, inputs: Vec<[[Block; N]; 2]>) -> Result<(), OTError> {
        let mut rng = ChaCha20Rng::from_entropy();

        // Prepare keys and convert inputs
        let keys: Vec<[Block; 2]> = (0..inputs.len())
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        // Zip the keys and inputs together and encrypt
        // We pack the buffer with the message ciphertexts in order
        let mut buffer: Vec<u8> = Vec::with_capacity(inputs.len() * 2 * N * Block::LEN);
        for ([key_0, key_1], [msg_0, msg_1]) in keys.iter().zip(inputs) {
            // Initialize ciphers with corresponding keys
            let (cipher_0, cipher_1) = (
                Aes128::new(&key_0.to_be_bytes().into()),
                Aes128::new(&key_1.to_be_bytes().into()),
            );

            let mut msg_0: [_; N] = std::array::from_fn(|i| msg_0[i].into());
            let mut msg_1: [_; N] = std::array::from_fn(|i| msg_1[i].into());

            // Encrypt the message blocks and push into buffer
            cipher_0.encrypt_blocks(&mut msg_0);
            cipher_1.encrypt_blocks(&mut msg_1);

            buffer.extend(msg_0.iter().chain(msg_1.iter()).flatten());
        }

        // Send keys using OT
        ObliviousSendOwned::<[Block; 2]>::send(self, keys).await?;

        // Send ciphertexts
        self.channel
            .send(OTMessage::ExtSenderEncryptedPayload(
                ExtSenderEncryptedPayload {
                    ciphertexts: buffer,
                },
            ))
            .await?;

        Ok(())
    }
}

#[async_trait]
impl ObliviousCommitOwned for Kos15IOSender<s_state::Initialized> {
    async fn commit(&mut self) -> Result<(), OTError> {
        let message = self.inner.commit_to_seed();
        self.channel
            .send(OTMessage::ExtSenderCommit(message))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ObliviousRevealOwned for Kos15IOSender<s_state::RandSetup> {
    async fn reveal(mut self) -> Result<(), OTError> {
        let message = unsafe { self.inner.reveal()? };
        self.channel
            .send(OTMessage::ExtSenderReveal(message))
            .await?;
        Ok(())
    }
}
