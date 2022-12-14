//! This module implements the IO layer of share-conversion for field elements of
//! GF(2^128), using oblivious transfer.

use async_trait::async_trait;
use share_conversion_core::gf2_128::{AddShare, Gf2_128ShareConvert, MulShare, OTEnvelope};

mod receiver;
pub mod recorder;
mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

use crate::ShareConversionError;

#[async_trait]
pub trait SendTape {
    async fn send_tape(self) -> Result<(), ShareConversionError>;
}

#[async_trait]
pub trait VerifyTape {
    async fn verify_tape(self) -> Result<bool, ShareConversionError>;
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::{AdditiveToMultiplicative, ConversionMessage, MultiplicativeToAdditive};

    use super::recorder::{Recorder, Tape, Void};
    use super::*;
    use mpc_aio::protocol::ot::mock::MockOTFactory;
    use mpc_core::Block;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use share_conversion_core::gf2_128::mul;
    use utils_aio::duplex::DuplexChannel;

    type Gf2ConversionChannel = DuplexChannel<ConversionMessage<ChaCha12Rng, u128>>;
    type Gf2Sender<U, V> = Sender<Arc<Mutex<MockOTFactory<Block>>>, U, V>;
    type Gf2Receiver<U, V> = Receiver<Arc<Mutex<MockOTFactory<Block>>>, U, V>;

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
            tokio::spawn(async move { sender.a_to_m(&random_numbers_1).await.unwrap() });
        let receiver_task =
            tokio::spawn(async move { receiver.a_to_m(&random_numbers_2).await.unwrap() });

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
            tokio::spawn(async move { sender.m_to_a(&random_numbers_1).await.unwrap() });
        let receiver_task =
            tokio::spawn(async move { receiver.m_to_a(&random_numbers_2).await.unwrap() });

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
            let _ = sender.a_to_m(&random_numbers_1).await.unwrap();
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.a_to_m(&random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        assert!(receiver_output);
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
            let _ = sender.m_to_a(&random_numbers_1).await.unwrap();
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.m_to_a(&random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        assert!(receiver_output);
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
            let _ = sender.a_to_m(&random_numbers_1).await.unwrap();

            // Malicious sender now changes his input in the tape before sending it
            *sender.tape_mut().sender_inputs.last_mut().unwrap() += 1;
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.a_to_m(&random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        assert!(!receiver_output);
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
            let _ = sender.m_to_a(&random_numbers_1).await.unwrap();

            // Malicious sender now changes his input in the tape before sending it
            *sender.tape_mut().sender_inputs.last_mut().unwrap() += 1;
            sender.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver.m_to_a(&random_numbers_2).await.unwrap();
            receiver.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        assert!(!receiver_output);
    }

    fn mock_converter_pair<U: Gf2_128ShareConvert, V: Recorder<U>>(
    ) -> (Gf2Sender<U, V>, Gf2Receiver<U, V>) {
        let (c1, c2): (Gf2ConversionChannel, Gf2ConversionChannel) = DuplexChannel::new();
        let ot_factory = Arc::new(Mutex::new(MockOTFactory::<Block>::default()));

        let sender = Sender::new(Arc::clone(&ot_factory), String::from(""), Box::new(c1));
        let receiver = Receiver::new(Arc::clone(&ot_factory), String::from(""), Box::new(c2));

        (sender, receiver)
    }

    fn get_random_gf2_128_vec(len: usize, rng: &mut ChaCha12Rng) -> Vec<u128> {
        (0..len).map(|_| rng.gen::<u128>()).collect()
    }
}
