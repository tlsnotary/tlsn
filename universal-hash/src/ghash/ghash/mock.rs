use share_conversion_aio::gf2_128::{
    mock::{mock_converter_pair, Gf2Receiver, Gf2Sender},
    recorder::Recorder,
};
use share_conversion_core::gf2_128::{AddShare, MulShare};

use super::{Ghash, GhashConfigBuilder};

pub type MockGhashSender<T, U> = Ghash<Gf2Sender<AddShare, T>, Gf2Sender<MulShare, U>>;
pub type MockGhashReceiver<T, U> = Ghash<Gf2Receiver<AddShare, T>, Gf2Receiver<MulShare, U>>;

/// Create a Ghash sender/receiver pair for testing purpose
pub fn mock_ghash_pair<T: Recorder<AddShare> + Send, U: Recorder<MulShare> + Send>(
    block_count: usize,
) -> (MockGhashSender<T, U>, MockGhashReceiver<T, U>) {
    let (sender_a2m, receiver_a2m) = mock_converter_pair::<AddShare, _>();
    let (sender_m2a, receiver_m2a) = mock_converter_pair::<MulShare, _>();

    let config = GhashConfigBuilder::default()
        .initial_block_count(block_count)
        .build()
        .unwrap();

    let (sender, receiver) = (
        Ghash::new(config.clone(), sender_a2m, sender_m2a),
        Ghash::new(config, receiver_a2m, receiver_m2a),
    );

    (sender, receiver)
}
