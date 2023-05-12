use std::sync::Arc;

use crate::{Converter, Role};
use mpc_share_conversion::{mock::mock_converter_pair, ReceiverConfig, SenderConfig};
use mpc_share_conversion_core::fields::p256::P256;

/// Create a pair of [Converter] instances
pub fn mock_point_converter_pair() -> (Converter<P256>, Converter<P256>) {
    let (leader_a2m, follower_a2m) = mock_converter_pair(
        SenderConfig::builder().id("a2m").build().unwrap(),
        ReceiverConfig::builder().id("a2m").build().unwrap(),
    );
    let (leader_m2a, follower_m2a) = mock_converter_pair(
        SenderConfig::builder().id("m2a").build().unwrap(),
        ReceiverConfig::builder().id("m2a").build().unwrap(),
    );
    (
        Converter::new(Arc::new(leader_a2m), Arc::new(leader_m2a), Role::Leader),
        Converter::new(
            Arc::new(follower_a2m),
            Arc::new(follower_m2a),
            Role::Follower,
        ),
    )
}
