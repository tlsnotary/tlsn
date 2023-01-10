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
        AdditiveToMultiplicative, MultiplicativeToAdditive,
    };
    use share_conversion_core::gf2_128::{mul, AddShare, Gf2_128ShareConvert, MulShare};
    use std::sync::{Arc, Mutex};
    use tokio::task::JoinError;
    use utils_aio::adaptive_barrier::AdaptiveBarrier;
    use xtra::prelude::*;

    use super::*;

    #[tokio::test]
    async fn test_actor_share_conversion_a2m() {
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
            create_conversion_controls::<AddShare>(None).await;

        let sender_task =
            tokio::spawn(async move { sender_control.a_to_m(random_numbers_1).await.unwrap() });
        let receiver_task =
            tokio::spawn(async move { receiver_control.a_to_m(random_numbers_2).await.unwrap() });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(mul(a, b), random_numbers[k]);
        }
    }

    #[tokio::test]
    async fn test_actor_share_conversion_m2a() {
        // Create some random numbers
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers: Vec<u128> =
            std::iter::zip(random_numbers_1.iter(), random_numbers_2.iter())
                .map(|(a, b)| mul(*a, *b))
                .collect();

        // Create conversion controls
        let (mut sender_control, mut receiver_control) =
            create_conversion_controls::<MulShare>(None).await;

        let sender_task =
            tokio::spawn(async move { sender_control.m_to_a(random_numbers_1).await.unwrap() });
        let receiver_task =
            tokio::spawn(async move { receiver_control.m_to_a(random_numbers_2).await.unwrap() });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(a ^ b, random_numbers[k]);
        }
    }

    #[tokio::test]
    async fn test_actor_share_conversion_multiple_executions() {
        // Create some random numbers
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let random_numbers_round_1_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_round_1_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_round_2_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_round_2_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);

        let random_numbers_round_1: Vec<u128> = std::iter::zip(
            random_numbers_round_1_1.iter(),
            random_numbers_round_1_2.iter(),
        )
        .map(|(a, b)| mul(*a, *b))
        .collect();

        let random_numbers_round_2: Vec<u128> = std::iter::zip(
            random_numbers_round_2_1.iter(),
            random_numbers_round_2_2.iter(),
        )
        .map(|(a, b)| mul(*a, *b))
        .collect();

        // Create conversion controls
        let (mut sender_control, mut receiver_control) =
            create_conversion_controls::<MulShare>(None).await;
        let (mut sender_control2, mut receiver_control2) =
            (sender_control.clone(), receiver_control.clone());

        // First round
        let sender_task = tokio::spawn(async move {
            sender_control
                .m_to_a(random_numbers_round_1_1)
                .await
                .unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver_control
                .m_to_a(random_numbers_round_1_2)
                .await
                .unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(a ^ b, random_numbers_round_1[k]);
        }

        // Second round
        let sender_task = tokio::spawn(async move {
            sender_control2
                .m_to_a(random_numbers_round_2_1)
                .await
                .unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver_control2
                .m_to_a(random_numbers_round_2_2)
                .await
                .unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // Check result
        for (k, (a, b)) in std::iter::zip(sender_output, receiver_output).enumerate() {
            assert_eq!(a ^ b, random_numbers_round_2[k]);
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
            create_conversion_controls::<AddShare>(None).await;

        let sender_task = tokio::spawn(async move {
            let _ = sender_control.a_to_m(random_numbers_1).await.unwrap();
            sender_control.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver_control.a_to_m(random_numbers_2).await.unwrap();
            receiver_control.verify_tape().await.unwrap()
        });

        let (sender_output, receiver_output) = tokio::join!(sender_task, receiver_task);
        let (_, _receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        // No need to check result, because if unwrap does not fail, this means everything works
        // fine.
    }

    #[tokio::test]
    // Make sure that the sender is correctly waiting at the barrier and is not sending the tape
    async fn test_actor_share_conversion_with_barrier() {
        // Create some random numbers
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let random_numbers_1: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);
        let random_numbers_2: Vec<u128> = get_random_gf2_128_vec(128, &mut rng);

        // Create a barrier
        let barrier = AdaptiveBarrier::new();
        // calling .wait() on `barrier` will return only when .wait() is called on `cloned_barrier`
        let _cloned_barrier = barrier.clone();

        // Create conversion controls
        let (mut sender_control, mut receiver_control) =
            create_conversion_controls::<AddShare>(Some(barrier)).await;

        let _sender_task = tokio::spawn(async move {
            let _ = sender_control.a_to_m(random_numbers_1).await.unwrap();
            sender_control.send_tape().await.unwrap()
        });
        let receiver_task = tokio::spawn(async move {
            receiver_control.a_to_m(random_numbers_2).await.unwrap();
            receiver_control.verify_tape().await.unwrap()
        });

        let timeout_duration = std::time::Duration::from_millis(200);
        // sender is .wait()ing at the barrier, so .send_tape() was not called and consequently
        // this causes the verifier to await on .verify_tape()
        let result = tokio::time::timeout(timeout_duration, receiver_task).await;

        fn print_type_of<T>(_: &T) -> String {
            std::any::type_name::<T>().to_string()
        }

        // since ::Elapsed is private, comparing the name string
        assert!(print_type_of(&result.err().unwrap()) == "tokio::time::error::Elapsed".to_string());
    }

    async fn create_conversion_controls<T: Gf2_128ShareConvert + Send + 'static>(
        barrier: Option<AdaptiveBarrier>,
    ) -> (
        SenderControl<
            ActorShareConversionSender<
                Arc<Mutex<MockOTFactory<Block>>>,
                MockOTSender<Block>,
                T,
                MockClientControl,
                Tape,
            >,
        >,
        ReceiverControl<
            ActorShareConversionReceiver<
                Arc<Mutex<MockOTFactory<Block>>>,
                MockOTReceiver<Block>,
                T,
                MockServerControl,
                Tape,
            >,
        >,
    ) {
        // Either party can play either role. Here we designate the Server to play the conversion Receiver
        // role and the Client to play the conversion Sender role.
        let receiver_mux_addr =
            xtra::spawn_tokio(MockServerChannelMuxer::default(), Mailbox::unbounded());
        let receiver_mux = MockServerControl::new(receiver_mux_addr.clone());

        let sender_mux_addr = xtra::spawn_tokio(
            MockClientChannelMuxer::new(receiver_mux_addr),
            Mailbox::unbounded(),
        );
        let sender_mux = MockClientControl::new(sender_mux_addr);

        let ot_factory = Arc::new(Mutex::new(MockOTFactory::<Block>::default()));
        let mut sender = ActorShareConversionSender::<_, _, T, _, Tape>::new(
            String::from(""),
            barrier,
            sender_mux,
            Arc::clone(&ot_factory),
        );
        let mut receiver = ActorShareConversionReceiver::<_, _, T, _, Tape>::new(
            String::from(""),
            receiver_mux,
            Arc::clone(&ot_factory),
        );

        sender.setup().await.unwrap();
        receiver.setup().await.unwrap();

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
