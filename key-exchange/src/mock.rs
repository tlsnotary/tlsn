//! This module provides mock types for key exchange leader and follower and a function to create
//! such a pair

use super::{
    exchange::KeyExchangeConfig,
    role::{Follower, Leader},
    KeyExchangeCore, KeyExchangeMessage,
};
use mpc_aio::protocol::{
    garble::{
        backend::RayonBackend,
        exec::dual::{state::Initialized, DualExFollower, DualExLeader},
        factory::dual::mock::{create_mock_dualex_factory, MockDualExFactory},
    },
    ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender},
};
use mpc_core::Block;
use point_addition::mock::{
    create_mock_point_converter_pair, MockPointConversionReceiver, MockPointConversionSender,
};
use utils_aio::duplex::DuplexChannel;

pub type MockKeyExchangeLeader = KeyExchangeCore<
    MockPointConversionSender,
    MockPointConversionReceiver,
    MockDualExFactory,
    DualExLeader<
        Initialized,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >,
    Leader,
>;

pub type MockKeyExchangeFollower = KeyExchangeCore<
    MockPointConversionReceiver,
    MockPointConversionSender,
    MockDualExFactory,
    DualExFollower<
        Initialized,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >,
    Follower,
>;

/// Create a mock pair of key exchange leader and follower
pub fn create_mock_key_exchange_pair() -> (MockKeyExchangeLeader, MockKeyExchangeFollower) {
    let (pa_leader1, pa_follower1) = create_mock_point_converter_pair();
    let (pa_leader2, pa_follower2) = create_mock_point_converter_pair();

    let dual_ex_factory = create_mock_dualex_factory();

    let (leader_channel, follower_channel) = DuplexChannel::<KeyExchangeMessage>::new();

    let leader = KeyExchangeCore::new(
        Box::new(leader_channel),
        pa_leader1,
        pa_follower2,
        dual_ex_factory.clone(),
        KeyExchangeConfig::new(String::from(""), Leader),
    );

    let follower = KeyExchangeCore::new(
        Box::new(follower_channel),
        pa_follower1,
        pa_leader2,
        dual_ex_factory,
        KeyExchangeConfig::new(String::from(""), Follower),
    );

    (leader, follower)
}
