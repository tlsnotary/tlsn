use futures::StreamExt;
use mpc_aio::protocol::ot::ObliviousReceive;
use mpc_core::Block;
use tls_2pc_core::{
    ghash::{Finalized, GhashReceiver, Init, Intermediate},
    msgs::ghash::GhashMessage,
};
use utils_aio::expect_msg_or_err;

use super::{GhashChannel, GhashIOError, GhashMac};

pub struct GhashIOReceiver<T: ObliviousReceive, U = Init> {
    inner: GhashReceiver<U>,
    channel: GhashChannel,
    ot_receiver: T,
}

impl<T: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>> GhashIOReceiver<T, Init> {
    pub fn new(
        hashkey: u128,
        max_message_length: usize,
        channel: GhashChannel,
        ot_receiver: T,
    ) -> Result<Self, GhashIOError> {
        let receiver = GhashReceiver::new(hashkey, max_message_length)?;
        Ok(Self {
            inner: receiver,
            channel,
            ot_receiver,
        })
    }

    pub async fn setup(mut self) -> Result<GhashIOReceiver<T, Finalized>, GhashIOError> {
        let _ = expect_msg_or_err!(
            self.channel.next().await,
            GhashMessage::SenderAddEnvelope,
            GhashIOError::Unexpected
        )?;

        let choices: Vec<bool> = self.inner.choices().into();
        let output = self.ot_receiver.receive(choices.as_slice()).await?;
        let receiver = self.inner.compute_mul_powers(output.into());

        let _ = expect_msg_or_err!(
            self.channel.next().await,
            GhashMessage::SenderMulEnvelope,
            GhashIOError::Unexpected
        )?;

        let choices: Vec<bool> = receiver.choices().expect("No choices during setup").into();
        let output = self.ot_receiver.receive(choices.as_slice()).await?;
        let receiver = receiver.into_add_powers(Some(output.into()));

        Ok(GhashIOReceiver {
            inner: receiver,
            channel: self.channel,
            ot_receiver: self.ot_receiver,
        })
    }
}
impl<T: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>> GhashIOReceiver<T, Intermediate> {
    pub async fn setup(mut self) -> Result<GhashIOReceiver<T, Finalized>, GhashIOError> {
        let choices = self.inner.choices();
        let output = if let Some(choices) = choices {
            let _ = expect_msg_or_err!(
                self.channel.next().await,
                GhashMessage::SenderMulEnvelope,
                GhashIOError::Unexpected
            )?;
            let choices: Vec<bool> = choices.into();
            Some(self.ot_receiver.receive(choices.as_slice()).await?)
        } else {
            None
        };
        let receiver = self.inner.into_add_powers(output.map(|inner| inner.into()));

        Ok(GhashIOReceiver {
            inner: receiver,
            channel: self.channel,
            ot_receiver: self.ot_receiver,
        })
    }
}

impl<T: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>> GhashIOReceiver<T, Finalized> {
    pub async fn change_message_length(
        self,
        new_message_length: usize,
    ) -> Result<GhashIOReceiver<T, Intermediate>, GhashIOError> {
        let receiver = GhashIOReceiver {
            inner: self.inner.change_max_hashkey(new_message_length),
            channel: self.channel,
            ot_receiver: self.ot_receiver,
        };

        Ok(receiver)
    }
}

impl<T: ObliviousReceive> GhashMac for GhashIOReceiver<T, Finalized>
where
    <T as ObliviousReceive>::Choice: From<&'static [bool]>,
{
    fn generate_mac(&self, message: &[u128]) -> Result<u128, GhashIOError> {
        self.inner.generate_mac(message).map_err(GhashIOError::from)
    }
}
