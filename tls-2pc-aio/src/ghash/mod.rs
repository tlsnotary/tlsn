use share_conversion_aio::ShareConversionError;
use tls_2pc_core::ghash::GhashError;

mod aio;
#[cfg(feature = "mock")]
pub mod mock;

pub use aio::GhashIO;

#[derive(Debug, thiserror::Error)]
pub enum GhashIOError {
    #[error("Ghash Error: {0}")]
    GhashError(#[from] GhashError),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Share conversion error: {0}")]
    ShareConversionError(#[from] ShareConversionError),
}

pub trait GhashOutput {
    fn generate_ghash_output(&self, message: &[u128]) -> Result<u128, GhashIOError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghash::mock::mock_ghash_pair;
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[tokio::test]
    async fn test_ghash_aio_output() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let message: Vec<u128> = (0..128).map(|_| rng.gen()).collect();

        let (sender, receiver) = mock_ghash_pair(h, message.len()).await;

        let sender = tokio::spawn(async move { sender.setup().await.unwrap() });
        let receiver = tokio::spawn(async move { receiver.setup().await.unwrap() });

        let (sender, receiver) = tokio::join!(sender, receiver);
        let (sender, receiver) = (sender.unwrap(), receiver.unwrap());

        let ghash_out_sender = sender.generate_ghash_output(&message).unwrap();
        let ghash_out_receiver = receiver.generate_ghash_output(&message).unwrap();

        assert_eq!(
            ghash_out_sender ^ ghash_out_receiver,
            ghash_reference_impl(h, message)
        );
    }

    #[tokio::test]
    async fn test_ghash_aio_long_message() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let short_message: Vec<u128> = (0..128).map(|_| rng.gen()).collect();

        // A longer message
        let long_message: Vec<u128> = (0..192).map(|_| rng.gen()).collect();
        let long_message_len = long_message.len();

        // Create and setup sender and receiver for short message length
        let (sender, receiver) = mock_ghash_pair(h, short_message.len()).await;

        let sender = tokio::spawn(async move { sender.setup().await.unwrap() });
        let receiver = tokio::spawn(async move { receiver.setup().await.unwrap() });

        let (sender, receiver) = tokio::join!(sender, receiver);
        let (sender, receiver) = (sender.unwrap(), receiver.unwrap());

        // Adapt for a longer message
        let (sender, receiver) = (
            sender.change_message_length(long_message_len),
            receiver.change_message_length(long_message_len),
        );

        // Compute more hashkey powers
        let sender = tokio::spawn(async move { sender.compute_add_shares().await.unwrap() });
        let receiver = tokio::spawn(async move { receiver.compute_add_shares().await.unwrap() });

        let (sender, receiver) = tokio::join!(sender, receiver);
        let (sender, receiver) = (sender.unwrap(), receiver.unwrap());

        // We should still be able to generate a ghash output for the shorter message
        let ghash_out_sender = sender.generate_ghash_output(&short_message).unwrap();
        let ghash_out_receiver = receiver.generate_ghash_output(&short_message).unwrap();

        assert_eq!(
            ghash_out_sender ^ ghash_out_receiver,
            ghash_reference_impl(h, short_message)
        );

        // Check if we can generate a ghash output for the long message now
        let ghash_out_sender = sender.generate_ghash_output(&long_message).unwrap();
        let ghash_out_receiver = receiver.generate_ghash_output(&long_message).unwrap();

        assert_eq!(
            ghash_out_sender ^ ghash_out_receiver,
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
}
