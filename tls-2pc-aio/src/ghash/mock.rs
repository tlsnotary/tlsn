use super::GhashIO;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use share_conversion_aio::gf2_128::{
    mock::{mock_converter_pair, Gf2Receiver, Gf2Sender},
    recorder::Void,
};
use share_conversion_core::gf2_128::{AddShare, MulShare};

pub async fn mock_ghash_pair(
    hashkey: u128,
    message_len: usize,
) -> (
    GhashIO<Gf2Sender<AddShare, Void>, Gf2Sender<MulShare, Void>>,
    GhashIO<Gf2Receiver<AddShare, Void>, Gf2Receiver<MulShare, Void>>,
) {
    let mut rng = ChaCha12Rng::from_seed([0; 32]);
    let h1: u128 = rng.gen();
    let h2 = hashkey ^ h1;

    let (sender_a2m, receiver_a2m) = mock_converter_pair::<AddShare, Void>();
    let (sender_m2a, receiver_m2a) = mock_converter_pair::<MulShare, Void>();

    let (sender, receiver) = (
        GhashIO::new(h1, message_len, sender_a2m, sender_m2a, String::from("")).unwrap(),
        GhashIO::new(
            h2,
            message_len,
            receiver_a2m,
            receiver_m2a,
            String::from(""),
        )
        .unwrap(),
    );

    (sender, receiver)
}
