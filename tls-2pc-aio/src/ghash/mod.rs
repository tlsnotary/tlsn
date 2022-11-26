use mpc_aio::protocol::ot::OTError;
use tls_2pc_core::{ghash::GhashError, msgs::ghash::GhashMessage};
use utils_aio::Channel;

mod receiver;
mod sender;

pub use {receiver::GhashIOReceiver, sender::GhashIOSender};

type GhashChannel = Box<dyn Channel<GhashMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum GhashIOError {
    #[error("Ghash Error: {0}")]
    GhashError(#[from] GhashError),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("OT error: {0}")]
    OTError(#[from] OTError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(GhashMessage),
}

pub trait GhashMac {
    fn generate_mac(&self, message: &[u128]) -> Result<u128, GhashIOError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghash_rc::universal_hash::{NewUniversalHash, UniversalHash};
    use ghash_rc::GHash;
    use mpc_aio::protocol::ot::kos::{receiver::Kos15IOReceiver, sender::Kos15IOSender};
    use mpc_core::msgs::ot::OTMessage;
    use mpc_core::ot::{r_state, s_state};
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use tls_2pc_core::ghash::Finalized;
    use utils_aio::duplex::DuplexChannel;

    #[tokio::test]
    async fn test_ghash_io_mac() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let message: Vec<u128> = (0..128).map(|_| rng.gen()).collect();

        let (ot_sender, ot_receiver) = setup_ot(2_usize.pow(14)).await;
        let (sender, receiver) = setup_ghash(rng, h, message.len(), ot_sender, ot_receiver).await;

        let mac1 = sender.generate_mac(&message).unwrap();
        let mac2 = receiver.generate_mac(&message).unwrap();

        assert_eq!(mac1 ^ mac2, ghash_reference_impl(h, message));
    }

    #[tokio::test]
    async fn test_ghash_io_long_message() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let short_message: Vec<u128> = (0..128).map(|_| rng.gen()).collect();

        // A longer message
        let long_message: Vec<u128> = (0..192).map(|_| rng.gen()).collect();
        let long_message_len = long_message.len();

        let (ot_sender, ot_receiver) = setup_ot(2_usize.pow(14)).await;
        let (sender, receiver) =
            setup_ghash(rng, h, short_message.len(), ot_sender, ot_receiver).await;

        // Compute more hashkey powers
        let sender = tokio::spawn(async move {
            sender
                .change_message_length(long_message_len)
                .await
                .unwrap()
        });
        let receiver = tokio::spawn(async move {
            let receiver = receiver
                .change_message_length(long_message_len)
                .await
                .unwrap();
            receiver.setup().await.unwrap()
        });
        let (sender, receiver) = tokio::join!(sender, receiver);
        let (sender, receiver) = (sender.unwrap(), receiver.unwrap());

        // We should still be able to generate a MAC for the shorter message
        let mac_short_1 = sender.generate_mac(&short_message).unwrap();
        let mac_short_2 = receiver.generate_mac(&short_message).unwrap();

        assert_eq!(
            mac_short_1 ^ mac_short_2,
            ghash_reference_impl(h, short_message)
        );

        // Check if we can generate a MAC for the long message now
        let mac_long_1 = sender.generate_mac(&long_message).unwrap();
        let mac_long_2 = receiver.generate_mac(&long_message).unwrap();

        assert_eq!(
            mac_long_1 ^ mac_long_2,
            ghash_reference_impl(h, long_message)
        );
    }

    fn ghash_reference_impl(h: u128, message: Vec<u128>) -> u128 {
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for el in message {
            ghash.update(&el.to_be_bytes().into());
        }
        let mac = ghash.finalize();
        u128::from_be_bytes(mac.into_bytes().try_into().unwrap())
    }

    async fn setup_ghash(
        mut rng: ChaCha12Rng,
        h: u128,
        message_len: usize,
        ot_sender: Kos15IOSender<s_state::RandSetup>,
        ot_receiver: Kos15IOReceiver<r_state::RandSetup>,
    ) -> (
        GhashIOSender<Kos15IOSender<s_state::RandSetup>, Finalized>,
        GhashIOReceiver<Kos15IOReceiver<r_state::RandSetup>, Finalized>,
    ) {
        let h1: u128 = rng.gen();
        let h2 = h ^ h1;

        let (c1, c2) = DuplexChannel::new();
        let sender = GhashIOSender::new(h1, message_len, Box::new(c1), ot_sender).unwrap();
        let receiver = GhashIOReceiver::new(h2, message_len, Box::new(c2), ot_receiver).unwrap();

        let sender = tokio::spawn(async move { sender.setup().await.unwrap() });
        let receiver = tokio::spawn(async move { receiver.setup().await.unwrap() });
        let (sender, receiver) = tokio::join!(sender, receiver);
        (sender.unwrap(), receiver.unwrap())
    }

    async fn setup_ot(
        max_ots: usize,
    ) -> (
        Kos15IOSender<s_state::RandSetup>,
        Kos15IOReceiver<r_state::RandSetup>,
    ) {
        let (c1, c2) = DuplexChannel::<OTMessage>::new();
        let (sender, receiver) = (
            Kos15IOSender::new(Box::new(c1)),
            Kos15IOReceiver::new(Box::new(c2)),
        );
        let sender = tokio::spawn(async move { sender.rand_setup(max_ots).await.unwrap() });
        let receiver = tokio::spawn(async move { receiver.rand_setup(max_ots).await.unwrap() });
        let (sender, receiver) = tokio::join!(sender, receiver);
        (sender.unwrap(), receiver.unwrap())
    }
}
