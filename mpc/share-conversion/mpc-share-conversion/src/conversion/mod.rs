mod config;
#[cfg(feature = "mock")]
pub mod mock;
mod receiver;
mod sender;
pub mod tape;

pub use config::{
    ReceiverConfig, ReceiverConfigBuilder, ReceiverConfigBuilderError, SenderConfig,
    SenderConfigBuilder, SenderConfigBuilderError,
};
pub use mpc_share_conversion_core::msgs::ShareConversionMessage;
pub use receiver::Receiver;
pub use sender::Sender;

use utils_aio::Channel;

/// A channel used by conversion protocols for messaging
pub type ShareConversionChannel<T> =
    Box<dyn Channel<ShareConversionMessage<T>, Error = std::io::Error> + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::{ReceiverConfig, SenderConfig};
    use crate::{
        conversion::mock::mock_converter_pair, AdditiveToMultiplicative, MultiplicativeToAdditive,
        SendTape, ShareConversionError, VerifyTape,
    };
    use mpc_share_conversion_core::{
        fields::{gf2_128::Gf2_128, p256::P256, Field},
        AddShare, MulShare,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    fn sender_config() -> SenderConfig {
        SenderConfig::builder().id("test").record().build().unwrap()
    }

    fn receiver_config() -> ReceiverConfig {
        ReceiverConfig::builder()
            .id("test")
            .record()
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_share_conversion_gf2_128_a2m() {
        test_a2m::<Gf2_128>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_gf2_128_m2a() {
        test_m2a::<Gf2_128>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_gf2_128_a2m_recorded() {
        test_a2m_recorded::<Gf2_128>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_gf2_128_m2a_recorded() {
        test_m2a_recorded::<Gf2_128>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_gf2_128_a2m_recorded_fail() {
        test_a2m_recorded_fail::<Gf2_128>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_gf2_128_m2a_recorded_fail() {
        test_m2a_recorded_fail::<Gf2_128>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_p256_a2m() {
        test_a2m::<P256>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_p256_m2a() {
        test_m2a::<P256>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_p256_a2m_recorded() {
        test_a2m_recorded::<P256>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_p256_m2a_recorded() {
        test_m2a_recorded::<P256>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_p256_a2m_recorded_fail() {
        test_a2m_recorded_fail::<P256>().await;
    }

    #[tokio::test]
    async fn test_share_conversion_p256_m2a_recorded_fail() {
        test_m2a_recorded_fail::<P256>().await;
    }

    async fn test_a2m<T: Field>() {
        let (sender, receiver) =
            mock_converter_pair::<AddShare<T>, T>(sender_config(), receiver_config());
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers_2: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers: Vec<T> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| *a + *b)
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
            assert_eq!(a * b, random_numbers[k]);
        }
    }

    async fn test_m2a<T: Field>() {
        let (sender, receiver) =
            mock_converter_pair::<MulShare<T>, T>(sender_config(), receiver_config());
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers_2: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers: Vec<T> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| *a * *b)
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
            assert_eq!(a + b, random_numbers[k]);
        }
    }

    async fn test_a2m_recorded<T: Field>() {
        let (sender, receiver) =
            mock_converter_pair::<AddShare<T>, T>(sender_config(), receiver_config());
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers_2: Vec<T> = get_random_field_vec(16, &mut rng);

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

    async fn test_m2a_recorded<T: Field>() {
        let (sender, receiver) =
            mock_converter_pair::<MulShare<T>, T>(sender_config(), receiver_config());
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers_2: Vec<T> = get_random_field_vec(16, &mut rng);

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

    async fn test_a2m_recorded_fail<T: Field>() {
        let (mut sender, receiver) =
            mock_converter_pair::<AddShare<T>, T>(sender_config(), receiver_config());
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers_2: Vec<T> = get_random_field_vec(16, &mut rng);

        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            let _ = sender.a_to_m(random_numbers_1).await.unwrap();

            // Malicious sender now changes his input in the tape before sending it
            *sender
                .state_mut()
                .tape
                .as_mut()
                .unwrap()
                .sender_inputs
                .last_mut()
                .unwrap() = T::one();
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

    async fn test_m2a_recorded_fail<T: Field>() {
        let (mut sender, receiver) =
            mock_converter_pair::<MulShare<T>, T>(sender_config(), receiver_config());
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create some random numbers
        let random_numbers_1: Vec<T> = get_random_field_vec(16, &mut rng);
        let random_numbers_2: Vec<T> = get_random_field_vec(16, &mut rng);
        // Spawn tokio tasks and wait for them to finish
        let sender_task = tokio::spawn(async move {
            let _ = sender.m_to_a(random_numbers_1).await.unwrap();

            // Malicious sender now changes his input in the tape before sending it
            *sender
                .state_mut()
                .tape
                .as_mut()
                .unwrap()
                .sender_inputs
                .last_mut()
                .unwrap() = T::one();
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

    fn get_random_field_vec<T: Field>(len: usize, rng: &mut ChaCha12Rng) -> Vec<T> {
        (0..len).map(|_| T::rand(rng)).collect()
    }
}
