mod receiver;
mod sender;

pub use receiver::{Receiver as ActorShareConversionReceiver, ReceiverControl};
pub use sender::{Sender as ActorShareConversionSender, SenderControl};

pub struct SendTapeMessage;
pub struct VerifyTapeMessage;
pub struct M2AMessage<T>(T);
pub struct A2MMessage<T>(T);

#[cfg(test)]
mod tests {
    use actor_mux::{
        MockClientChannelMuxer, MockClientControl, MockServerChannelMuxer, MockServerControl,
    };
    use mpc_aio::protocol::ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
    use mpc_core::Block;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use share_conversion_aio::{
        gf2_128::{recorder::Tape, SendTape, VerifyTape},
        AdditiveToMultiplicative,
    };
    use share_conversion_core::gf2_128::{mul, AddShare, Gf2_128ShareConvert};
    use std::sync::{Arc, Mutex};
    use xtra::prelude::*;

    use super::*;

    #[tokio::test]
    async fn test_actor_share_conversion() {
        // Create some random numbers
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers: Vec<u128> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| a ^ b)
                .collect();

        // Create conversion controls
        let (mut sender_control, mut receiver_control) =
            create_conversion_controls::<AddShare>().await;

        let sender_task =
            tokio::spawn(async move { sender_control.a_to_m(&random_numbers_1).await.unwrap() });
        let receiver_task =
            tokio::spawn(async move { receiver_control.a_to_m(&random_numbers_2).await.unwrap() });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(mul(a, b), random_numbers[k]);
        }
    }

    #[tokio::test]
    async fn test_actor_share_conversion_recorded() {
        // Create some random numbers
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);

        // Create conversion controls
        let (mut sender_control, mut receiver_control) =
            create_conversion_controls::<AddShare>().await;

        let sender_task = tokio::spawn(async move {
            let _ = sender_control.a_to_m(&random_numbers_1).await.unwrap();
            sender_control.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver_control.a_to_m(&random_numbers_2).await.unwrap();
            receiver_control.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, _receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // No need to check result, because if unwrap does not fail, this means everything works
        // fine.
    }

    async fn create_conversion_controls<T: Gf2_128ShareConvert + Send + 'static>() -> (
        SenderControl<
            ActorShareConversionSender<
                Arc<Mutex<MockOTFactory<Block>>>,
                MockOTSender<Block>,
                T,
                Tape,
            >,
        >,
        ReceiverControl<
            ActorShareConversionReceiver<
                Arc<Mutex<MockOTFactory<Block>>>,
                MockOTReceiver<Block>,
                T,
                Tape,
            >,
        >,
    ) {
        let receiver_mux_addr =
            xtra::spawn_tokio(MockServerChannelMuxer::default(), Mailbox::unbounded());
        let receiver_mux = MockServerControl::new(receiver_mux_addr.clone());

        let sender_mux_addr = xtra::spawn_tokio(
            MockClientChannelMuxer::new(receiver_mux_addr),
            Mailbox::unbounded(),
        );
        let sender_mux = MockClientControl::new(sender_mux_addr);

        let ot_factory = Arc::new(Mutex::new(MockOTFactory::<Block>::default()));

        let sender = ActorShareConversionSender::<_, _, T, Tape>::new(
            sender_mux,
            Arc::clone(&ot_factory),
            String::from(""),
            None,
        )
        .await
        .unwrap();
        let receiver = ActorShareConversionReceiver::<_, _, T, Tape>::new(
            receiver_mux,
            Arc::clone(&ot_factory),
            String::from(""),
        )
        .await
        .unwrap();

        let sender_addr = xtra::spawn_tokio(sender, Mailbox::unbounded());
        let receiver_addr = xtra::spawn_tokio(receiver, Mailbox::unbounded());

        let sender_control = SenderControl::new(sender_addr);
        let receiver_control = ReceiverControl::new(receiver_addr);

        (sender_control, receiver_control)
    }

    fn get_random_gf2_128_vec(len: usize, rng: &mut ChaCha12Rng) -> Vec<u128> {
        (0..len).map(|_| rng.gen::<u128>()).collect()
    }
}
