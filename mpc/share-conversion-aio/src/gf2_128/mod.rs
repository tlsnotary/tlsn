//! This module implements the IO layer of share-conversion for field elements of
//! GF(2^128), using oblivious transfer.

use async_trait::async_trait;
use share_conversion_core::gf2_128::{AddShare, Gf2_128ShareConvert, MulShare, OTEnvelope};
use utils_aio::Channel;

mod msgs;
mod receiver;
pub mod recorder;
mod sender;

#[cfg(feature = "mock")]
pub mod mock;

pub use msgs::Gf2ConversionMessage;
pub use receiver::Receiver;
pub use sender::Sender;

use crate::ShareConversionError;

/// Send a tape used for verification of the conversion
///
/// Implementers record their inputs used during conversion and can send them to the other
/// party. This will allow the other party to compute all outputs of the sender.
#[async_trait]
pub trait SendTape {
    async fn send_tape(self) -> Result<(), ShareConversionError>;
}

/// Verify the recorded inputs of the other party
///
/// Will check if the conversion worked correctly. This allows to catch a malicious party but
/// requires the malicious party to open and send all their inputs of the conversion before.
#[async_trait]
pub trait VerifyTape {
    async fn verify_tape(self) -> Result<(), ShareConversionError>;
}

/// A channel used for messaging of conversion protocols
pub type Gf2ConversionChannel = Box<dyn Channel<Gf2ConversionMessage, Error = std::io::Error>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gf2_128::mock::mock_converter_pair, AdditiveToMultiplicative, MultiplicativeToAdditive,
        ShareConversionError,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use recorder::{Tape, Void};
    use share_conversion_core::gf2_128::mul;

    #[tokio::test]
    async fn test_aio_a2m() {
        let (mut sender, mut receiver) = mock_converter_pair::<AddShare, Void>();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers: Vec<u128> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| a ^ b)
                .collect();

        // Spawn tokio tasks and wait for them to finish
        let sender_task =
            tokio::spawn(async move { sender.a_to_m(random_numbers_1).await.unwrap() });
        let receiver_task =
            tokio::spawn(async move { receiver.a_to_m(random_numbers_2).await.unwrap() });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(mul(a, b), random_numbers[k]);
        }
    }

    #[tokio::test]
    async fn test_aio_m2a() {
        let (mut sender, mut receiver) = mock_converter_pair::<MulShare, Void>();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers: Vec<u128> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| mul(*a, *b))
                .collect();

        // Spawn tokio tasks and wait for them to finish
        let sender_task =
            tokio::spawn(async move { sender.m_to_a(random_numbers_1).await.unwrap() });
        let receiver_task =
            tokio::spawn(async move { receiver.m_to_a(random_numbers_2).await.unwrap() });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(a ^ b, random_numbers[k]);
        }
    }

    #[tokio::test]
    async fn test_aio_a2m_recorded() {
        let (mut sender, mut receiver) = mock_converter_pair::<AddShare, Tape>();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);

        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            let _ = sender.a_to_m(random_numbers_1).await.unwrap();
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.a_to_m(random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, _receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // No need to check result, because if unwrap does not fail, this means everything works
        // fine.
    }

    #[tokio::test]
    async fn test_aio_m2a_recorded() {
        let (mut sender, mut receiver) = mock_converter_pair::<MulShare, Tape>();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);

        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            let _ = sender.m_to_a(random_numbers_1).await.unwrap();
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.m_to_a(random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, _receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // No need to check result, because if unwrap does not fail, this means everything works
        // fine.
    }

    #[tokio::test]
    async fn test_aio_a2m_recorded_fail() {
        let (mut sender, mut receiver) = mock_converter_pair::<AddShare, Tape>();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);

        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            let _ = sender.a_to_m(random_numbers_1).await.unwrap();

            // Malicious sender now changes his input in the tape before sending it
            *sender.tape_mut().sender_inputs.last_mut().unwrap() += 1;
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.a_to_m(random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap_err()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        assert!(matches!(
            receiver_output,
            ShareConversionError::VerifyTapeFailed
        ));
    }

    #[tokio::test]
    async fn test_aio_m2a_recorded_fail() {
        let (mut sender, mut receiver) = mock_converter_pair::<MulShare, Tape>();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);

        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            let _ = sender.m_to_a(random_numbers_1).await.unwrap();

            // Malicious sender now changes his input in the tape before sending it
            *sender.tape_mut().sender_inputs.last_mut().unwrap() += 1;
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.m_to_a(random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap_err()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        assert!(matches!(
            receiver_output,
            ShareConversionError::VerifyTapeFailed
        ));
    }

    fn get_random_gf2_128_vec(len: usize, rng: &mut ChaCha12Rng) -> Vec<u128> {
        (0..len).map(|_| rng.gen::<u128>()).collect()
    }
}
