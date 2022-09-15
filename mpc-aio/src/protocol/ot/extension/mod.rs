pub mod receiver;
pub mod sender;

use super::{OTChannel, ObliviousReceive, ObliviousSend, ObliviousTransfer, Protocol};

#[cfg(test)]
mod tests {

    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use super::receiver::Kos15IOReceiver;
    use super::sender::Kos15IOSender;
    use super::ObliviousTransfer;
    use crate::protocol::duplex::DuplexChannel;

    #[tokio::test]
    async fn test_mpc_aio_kos_setup() {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut choices = vec![false; 1024];
        rng.fill::<[bool]>(&mut choices);

        let (channel, channel_2) = DuplexChannel::<ObliviousTransfer>::new();
        let (sender, receiver) = (
            Kos15IOSender::new(Box::pin(channel)),
            Kos15IOReceiver::new(Box::pin(channel_2)),
        );
        let send = tokio::spawn(async { sender.setup().await.unwrap() });
        let receive = tokio::spawn(async move { receiver.setup(&choices).await.unwrap() });
        let (_sender, _receiver) = tokio::join!(send, receive);
        assert!(true)
    }
}
