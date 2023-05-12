use std::sync::Arc;

use mpc_share_conversion::{mock::mock_converter_pair, ReceiverConfig, SenderConfig};
use mpc_share_conversion_core::{fields::gf2_128::Gf2_128, AddShare, MulShare};

use super::{Ghash, GhashConfig};

/// Create a Ghash sender/receiver pair for testing purpose
pub fn mock_ghash_pair(sender_config: GhashConfig, receiver_config: GhashConfig) -> (Ghash, Ghash) {
    let (sender_a2m, receiver_a2m) = mock_converter_pair::<AddShare<Gf2_128>, Gf2_128>(
        SenderConfig::builder()
            .id(format!("{}/a2m", sender_config.id))
            .record()
            .build()
            .unwrap(),
        ReceiverConfig::builder()
            .id(format!("{}/a2m", receiver_config.id))
            .record()
            .build()
            .unwrap(),
    );
    let (sender_m2a, receiver_m2a) = mock_converter_pair::<MulShare<Gf2_128>, Gf2_128>(
        SenderConfig::builder()
            .id(format!("{}/m2a", sender_config.id))
            .record()
            .build()
            .unwrap(),
        ReceiverConfig::builder()
            .id(format!("{}/m2a", receiver_config.id))
            .record()
            .build()
            .unwrap(),
    );

    let (sender, receiver) = (
        Ghash::new(sender_config, Arc::new(sender_a2m), Arc::new(sender_m2a)),
        Ghash::new(
            receiver_config,
            Arc::new(receiver_a2m),
            Arc::new(receiver_m2a),
        ),
    );

    (sender, receiver)
}
