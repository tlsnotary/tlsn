use m2a_2pc::{mul_gf2_128, AddShare, MaskedEncoding, MulShare};
use mpc_aio::protocol::ot::kos::receiver::Kos15IOReceiver;
use mpc_aio::protocol::ot::kos::sender::Kos15IOSender;
use mpc_aio::protocol::ot::{ObliviousReceive, ObliviousSend};
use mpc_core::msgs::ot::OTMessage;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use utils_aio::duplex::DuplexChannel;

pub mod helper;
use helper::{interleave_to_blocks, u128_to_bool};

#[tokio::test]
async fn test_m2a_ot() {
    async fn test_mpc_aio_kos_random() {
        let mut rng = ChaCha12Rng::from_entropy();

        // Prepare multiplicative shares and encoding
        let a: MulShare = MulShare::new(rng.gen());
        let b: MulShare = MulShare::new(rng.gen());
        let (x, MaskedEncoding(t0, t1)) = a.encode();

        // Prepare inputs/outputs for OT
        let choices = u128_to_bool(b.inner());
        let blocks = interleave_to_blocks((t0, t1));

        //Send via KOS OT
        let (channel, channel_2) = DuplexChannel::<OTMessage>::new();
        let (sender, receiver) = (
            Kos15IOSender::new(Box::new(channel)),
            Kos15IOReceiver::new(Box::new(channel_2)),
        );
        let send = tokio::spawn(async {
            let mut sender = sender.rand_setup().await.unwrap();
            sender.send(blocks).await.unwrap();
        });
        let receive = tokio::spawn(async move {
            let mut receiver = receiver.rand_setup(128).await.unwrap();
            receiver.receive(&choices).await.unwrap()
        });

        let (_, output) = tokio::join!(send, receive);

        // Turn output into additive share for receiver
        let output: [u128; 128] = output
            .unwrap()
            .iter()
            .map(|block| block.inner())
            .collect::<Vec<u128>>()
            .try_into()
            .unwrap();
        let y = AddShare::from(output);

        assert_eq!(mul_gf2_128(a.inner(), b.inner()), x.inner() ^ y.inner());
    }
}
