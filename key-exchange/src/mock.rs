//! This module provides mock types for key exchange leader and follower and a function to create
//! such a pair

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

use crate::{
    exchange::Role,
    state::{KeyExchangeSetup, PMSComputationSetup},
    KeyExchangeMessage,
};

use super::KeyExchangeCore;

pub type MockKeyExchangeLeader = KeyExchangeCore<
    KeyExchangeSetup<
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
    >,
>;

pub type MockKeyExchangeLeaderPMSSetup = KeyExchangeCore<
    PMSComputationSetup<
        MockPointConversionSender,
        MockPointConversionReceiver,
        DualExLeader<
            Initialized,
            RayonBackend,
            MockOTFactory<Block>,
            MockOTFactory<Block>,
            MockOTSender<Block>,
            MockOTReceiver<Block>,
        >,
    >,
>;

pub type MockKeyExchangeFollower = KeyExchangeCore<
    KeyExchangeSetup<
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
    >,
>;

pub type MockKeyExchangeFollowerPMSSetup = KeyExchangeCore<
    PMSComputationSetup<
        MockPointConversionReceiver,
        MockPointConversionSender,
        DualExFollower<
            Initialized,
            RayonBackend,
            MockOTFactory<Block>,
            MockOTFactory<Block>,
            MockOTSender<Block>,
            MockOTReceiver<Block>,
        >,
    >,
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
        Role::Leader,
    );

    let follower = KeyExchangeCore::new(
        Box::new(follower_channel),
        pa_follower1,
        pa_leader2,
        dual_ex_factory,
        Role::Follower,
    );

    (leader, follower)
}
