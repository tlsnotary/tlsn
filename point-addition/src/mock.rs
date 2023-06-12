use crate::{MpcPointAddition, Role};
use mpc_share_conversion::{
    mock::{mock_converter_pair, MockConverterReceiver, MockConverterSender},
    ReceiverConfig, SenderConfig,
};
use mpc_share_conversion_core::fields::p256::P256;

/// A mock point addition sender implementing [MpcPointAddition] for [P256]
pub type MockPointAdditionSender = MpcPointAddition<P256, MockConverterSender<P256>>;

/// A mock point addition receiver implementing [MpcPointAddition] for [P256]
pub type MockPointAdditionReceiver = MpcPointAddition<P256, MockConverterReceiver<P256>>;

/// Create a pair of [MpcPointAddition] instances
pub fn mock_point_converter_pair(id: &str) -> (MockPointAdditionSender, MockPointAdditionReceiver) {
    let (sender, receiver) = mock_converter_pair(
        SenderConfig::builder()
            .id(format!("{}/converter", id))
            .build()
            .unwrap(),
        ReceiverConfig::builder()
            .id(format!("{}/converter", id))
            .build()
            .unwrap(),
    );
    (
        MpcPointAddition::new(Role::Leader, sender),
        MpcPointAddition::new(Role::Follower, receiver),
    )
}
