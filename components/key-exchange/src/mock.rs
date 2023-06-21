//! This module provides mock types for key exchange leader and follower and a function to create
//! such a pair

use crate::{KeyExchangeConfig, KeyExchangeCore, KeyExchangeMessage, Role};

use mpz_garble::{Decode, Execute, Memory};
use point_addition::mock::{
    mock_point_converter_pair, MockPointAdditionReceiver, MockPointAdditionSender,
};
use utils_aio::duplex::DuplexChannel;

/// A mock key exchange instance
pub type MockKeyExchange<E> =
    KeyExchangeCore<MockPointAdditionSender, MockPointAdditionReceiver, E>;

/// Create a mock pair of key exchange leader and follower
pub fn create_mock_key_exchange_pair<E: Memory + Execute + Decode + Send>(
    id: &str,
    leader_executor: E,
    follower_executor: E,
) -> (MockKeyExchange<E>, MockKeyExchange<E>) {
    let (leader_pa_sender, follower_pa_recvr) = mock_point_converter_pair(&format!("{}/pa/0", id));
    let (follower_pa_sender, leader_pa_recvr) = mock_point_converter_pair(&format!("{}/pa/1", id));

    let (leader_channel, follower_channel) = DuplexChannel::<KeyExchangeMessage>::new();

    let key_exchange_config_leader = KeyExchangeConfig::builder()
        .id(id)
        .role(Role::Leader)
        .build()
        .unwrap();

    let key_exchange_config_follower = KeyExchangeConfig::builder()
        .id(id)
        .role(Role::Follower)
        .build()
        .unwrap();

    let leader = KeyExchangeCore::new(
        Box::new(leader_channel),
        leader_pa_sender,
        leader_pa_recvr,
        leader_executor,
        key_exchange_config_leader,
    );

    let follower = KeyExchangeCore::new(
        Box::new(follower_channel),
        follower_pa_sender,
        follower_pa_recvr,
        follower_executor,
        key_exchange_config_follower,
    );

    (leader, follower)
}
