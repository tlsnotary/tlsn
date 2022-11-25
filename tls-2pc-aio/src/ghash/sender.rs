use futures::SinkExt;
use mpc_aio::protocol::ot::ObliviousSend;
use tls_2pc_core::{
    ghash::{Finalized, GhashSender, Init, SenderAddSharing, SenderMulSharing},
    msgs::ghash::GhashMessage,
};

use super::{GhashChannel, GhashIOError, GhashMac};

pub struct GhashIOSender<T: ObliviousSend, U = Init> {
    inner: GhashSender<U>,
    channel: GhashChannel,
    ot_sender: T,
}

impl<T: ObliviousSend> GhashIOSender<T, Init>
where
    <T as ObliviousSend>::Inputs: From<SenderAddSharing> + From<SenderMulSharing>,
{
    pub fn new(
        hashkey: u128,
        max_message_length: usize,
        channel: GhashChannel,
        ot_sender: T,
    ) -> Result<Self, GhashIOError> {
        let sender = GhashSender::new(hashkey, max_message_length)?;
        Ok(Self {
            inner: sender,
            channel,
            ot_sender,
        })
    }

    pub async fn setup(mut self) -> Result<GhashIOSender<T, Finalized>, GhashIOError> {
        let (sender, message) = self.inner.compute_mul_powers();

        let messages = futures::join!(
            self.ot_sender.send(message.into()),
            self.channel.send(GhashMessage::SenderAddEnvelope)
        );
        let (_, _) = (messages.0?, messages.1?);

        let (sender, message) = sender.into_add_powers();

        let messages = futures::join!(
            self.ot_sender.send(message.into()),
            self.channel.send(GhashMessage::SenderMulEnvelope)
        );
        let (_, _) = (messages.0?, messages.1?);

        Ok(GhashIOSender {
            inner: sender,
            channel: self.channel,
            ot_sender: self.ot_sender,
        })
    }
}

impl<T: ObliviousSend> GhashIOSender<T, Finalized>
where
    <T as ObliviousSend>::Inputs: From<SenderMulSharing>,
{
    pub async fn change_message_length(
        mut self,
        new_message_length: usize,
    ) -> Result<Self, GhashIOError> {
        let (sender, message) = self.inner.change_max_hashkey(new_message_length);

        if let Some(message) = message {
            let messages = futures::join!(
                self.ot_sender.send(message.into()),
                self.channel.send(GhashMessage::SenderMulEnvelope)
            );
            let (_, _) = (messages.0?, messages.1?);
        }

        Ok(GhashIOSender {
            inner: sender,
            channel: self.channel,
            ot_sender: self.ot_sender,
        })
    }
}

impl<T: ObliviousSend> GhashMac for GhashIOSender<T, Finalized> {
    fn generate_mac(&self, message: &[u128]) -> Result<u128, GhashIOError> {
        self.inner.generate_mac(message).map_err(GhashIOError::from)
    }
}
