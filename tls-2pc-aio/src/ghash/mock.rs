use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use share_conversion_aio::gf2_128::{
    mock::{mock_converter_pair, Gf2Receiver, Gf2Sender},
    recorder::Recorder,
};
use share_conversion_core::gf2_128::{AddShare, MulShare};

use super::{GhashReceiver, GhashSender};

pub type MockGhashSender<T, U> = GhashSender<Gf2Sender<AddShare, T>, Gf2Sender<MulShare, U>>;
pub type MockGhashReceiver<T, U> =
    GhashReceiver<Gf2Receiver<AddShare, T>, Gf2Receiver<MulShare, U>>;

pub fn mock_ghash_pair<T: Recorder<AddShare> + Send, U: Recorder<MulShare> + Send>(
    hashkey: u128,
    message_len: usize,
) -> (MockGhashSender<T, U>, MockGhashReceiver<T, U>) {
    let mut rng = ChaCha12Rng::from_seed([0; 32]);
    let h1: u128 = rng.gen();
    let h2 = hashkey ^ h1;

    let (sender_a2m, receiver_a2m) = mock_converter_pair::<AddShare, _>();
    let (sender_m2a, receiver_m2a) = mock_converter_pair::<MulShare, _>();

    let (sender, receiver) = (
        GhashSender::new(h1, message_len, sender_a2m, sender_m2a, String::from("")).unwrap(),
        GhashReceiver::new(
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
