use mpc_core::Block;
use mpc_share_conversion::conversion::{
    mock::{mock_converter_pair, MockReceiver, MockSender},
    recorder::Recorder,
};
use mpc_share_conversion_core::{fields::gf2_128::Gf2_128, AddShare, MulShare};

use super::{Ghash, GhashConfigBuilder};

pub type MockGhashSender<T, U> = Ghash<
    MockSender<AddShare<Gf2_128>, Gf2_128, Block, T>,
    MockSender<MulShare<Gf2_128>, Gf2_128, Block, U>,
>;
pub type MockGhashReceiver<T, U> = Ghash<
    MockReceiver<AddShare<Gf2_128>, Gf2_128, Block, T>,
    MockReceiver<MulShare<Gf2_128>, Gf2_128, Block, U>,
>;

/// Create a Ghash sender/receiver pair for testing purpose
pub fn mock_ghash_pair<T, U>(block_count: usize) -> (MockGhashSender<T, U>, MockGhashReceiver<T, U>)
where
    T: Recorder<AddShare<Gf2_128>, Gf2_128> + Send,
    U: Recorder<MulShare<Gf2_128>, Gf2_128> + Send,
{
    let (sender_a2m, receiver_a2m) = mock_converter_pair::<AddShare<Gf2_128>, _, _, _>();
    let (sender_m2a, receiver_m2a) = mock_converter_pair::<MulShare<Gf2_128>, _, _, _>();

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
