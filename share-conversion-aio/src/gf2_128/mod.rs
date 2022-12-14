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

    use super::*;
    use mpc_aio::protocol::ot::mock::MockOTFactory;
    use mpc_core::Block;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use share_conversion_core::gf2_128::mul;

    #[tokio::test]
    async fn test_aio_a2m() {
        let (mut sender, mut receiver) = mock_converter_pair();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers: Vec<u128> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| a ^ b)
                .collect();

        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            sender
                .convert_from::<AddShare, _>(&random_numbers_1, &mut rng)
                .await
                .unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver
                .convert_from::<AddShare>(&random_numbers_2)
                .await
                .unwrap()
        });
        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(mul(a, b), random_numbers[k]);
        }
    }

    #[tokio::test]
    async fn test_aio_m2a() {
        let (mut sender, mut receiver) = mock_converter_pair();
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers: Vec<u128> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| mul(*a, *b))
                .collect();

        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            sender
                .convert_from::<MulShare, _>(&random_numbers_1, &mut rng)
                .await
                .unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver
                .convert_from::<MulShare>(&random_numbers_2)
                .await
                .unwrap()
        });
        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(a ^ b, random_numbers[k]);
        }
    }

    fn mock_converter_pair<U: Gf2_128ShareConvert>() -> (
        Sender<Arc<Mutex<MockOTFactory<Block>>>, U>,
        Receiver<Arc<Mutex<MockOTFactory<Block>>>, U>,
    ) {
        let ot_factory = Arc::new(Mutex::new(MockOTFactory::<Block>::default()));
        let sender = Sender::new(Arc::clone(&ot_factory), String::from(""));
        let receiver = Receiver::new(Arc::clone(&ot_factory), String::from(""));
        (sender, receiver)
    }

    fn get_random_gf2_128_vec(len: usize, rng: &mut ChaCha12Rng) -> Vec<u128> {
        (0..len).map(|_| rng.gen::<u128>()).collect()
    }
}
