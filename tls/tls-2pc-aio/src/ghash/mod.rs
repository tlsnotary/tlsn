use share_conversion_aio::ShareConversionError;
use tls_2pc_core::ghash::GhashError as GhashCoreError;

/// Contains the logic which is used by both sender and receiver
mod aio;
#[cfg(feature = "mock")]
pub mod mock;

pub use aio::Ghash;

#[derive(Debug, thiserror::Error)]
pub enum GhashError {
    #[error("Ghash Error: {0}")]
    CoreError(#[from] GhashCoreError),
    #[error("Share conversion error: {0}")]
    ShareConversionError(#[from] ShareConversionError),
    #[error("Error: {0}")]
    Other(String),
}

/// Create a Ghash output for some message
///
/// The Ghash output is the unencrypted GCM MAC (i.e. before the XOR of the GCTR block)
pub trait GenerateGhash {
    fn finalize(&self, message: &[u128]) -> Result<u128, GhashError>;
}

#[cfg(test)]
mod tests {
    use super::{mock::mock_ghash_pair, GenerateGhash};
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use share_conversion_aio::gf2_128::recorder::Void;

    #[tokio::test]
    async fn test_ghash_aio_output() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let message: Vec<u128> = (0..128).map(|_| rng.gen()).collect();

        let (sender, receiver) = mock_ghash_pair::<Void, Void>(h, message.len());

        let sender = tokio::spawn(async move { sender.setup().await.unwrap() });
        let receiver = tokio::spawn(async move { receiver.setup().await.unwrap() });

        let (sender, receiver) = tokio::join!(sender, receiver);
        let (sender, receiver) = (sender.unwrap(), receiver.unwrap());

        let ghash_out_sender = sender.finalize(&message).unwrap();
        let ghash_out_receiver = receiver.finalize(&message).unwrap();

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
        let (sender, receiver) = mock_ghash_pair::<Void, Void>(h, short_message.len());

        let sender = tokio::spawn(async move { sender.setup().await.unwrap() });
        let receiver = tokio::spawn(async move { receiver.setup().await.unwrap() });

        let (sender, receiver) = tokio::join!(sender, receiver);
        let (sender, receiver) = (sender.unwrap(), receiver.unwrap());

        // Adapt for a longer message
        let (sender, receiver) = (
            sender.change_message_length(long_message_len),
            receiver.change_message_length(long_message_len),
        );

        let (sender, receiver) = tokio::join!(sender, receiver);
        let (sender, receiver) = (sender.unwrap(), receiver.unwrap());

        // We should still be able to generate a Ghash output for the shorter message
        let ghash_out_sender = sender.finalize(&short_message).unwrap();
        let ghash_out_receiver = receiver.finalize(&short_message).unwrap();

        assert_eq!(
            ghash_out_sender ^ ghash_out_receiver,
            ghash_reference_impl(h, short_message)
        );

        // Check if we can generate a Ghash output for the long message now
        let ghash_out_sender = sender.finalize(&long_message).unwrap();
        let ghash_out_receiver = receiver.finalize(&long_message).unwrap();

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
