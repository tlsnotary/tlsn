//! This module provides mock types for key exchange leader and follower and a function to create
//! such a pair

use super::{
    config::KeyExchangeConfigBuilder,
    role::{Follower, Leader},
    KeyExchangeCore, KeyExchangeMessage,
};
use futures::lock::Mutex;
use mpc_circuits::BitOrder;
use mpc_core::Block;
use mpc_garble::{
    backend::RayonBackend,
    exec::dual::{state::Initialized, DualExFollower, DualExLeader},
    factory::dual::mock::{create_mock_dualex_factory, MockDualExFactory},
};
use mpc_garble_core::ChaChaEncoder;
use mpc_ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
use point_addition::mock::{
    create_mock_point_converter_pair, MockPointConversionReceiver, MockPointConversionSender,
};
use std::sync::Arc;
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
    let key_exchange_config_leader = KeyExchangeConfigBuilder::default()
        .id(String::from(""))
        .role(Leader)
        .build()
        .unwrap();

    let key_exchange_config_follower = KeyExchangeConfigBuilder::default()
        .id(String::from(""))
        .role(Follower)
        .build()
        .unwrap();

    let mut leader = KeyExchangeCore::new(
        Box::new(leader_channel),
        pa_leader1,
        pa_follower2,
        dual_ex_factory.clone(),
        key_exchange_config_leader,
    );
    leader.set_encoder(Arc::new(Mutex::new(ChaChaEncoder::new(
        [0; 32],
        BitOrder::Lsb0,
    ))));

    let mut follower = KeyExchangeCore::new(
        Box::new(follower_channel),
        pa_follower1,
        pa_leader2,
        dual_ex_factory,
        key_exchange_config_follower,
    );
    follower.set_encoder(Arc::new(Mutex::new(ChaChaEncoder::new(
        [0; 32],
        BitOrder::Lsb0,
    ))));

    (leader, follower)
}
