use mpz_share_conversion::{
    mock::{mock_converter_pair, MockConverterReceiver, MockConverterSender},
    Gf2_128, ReceiverConfig, SenderConfig,
};

use super::{Ghash, GhashConfig};

/// Create a Ghash sender/receiver pair for testing purpose.
pub fn mock_ghash_pair(
    sender_config: GhashConfig,
    receiver_config: GhashConfig,
) -> (
    Ghash<MockConverterSender<Gf2_128>>,
    Ghash<MockConverterReceiver<Gf2_128>>,
) {
    let (sender, receiver) = mock_converter_pair::<Gf2_128>(
        SenderConfig::builder()
            .id(format!("{}/converter", sender_config.id))
            .record()
            .build()
            .unwrap(),
        ReceiverConfig::builder()
            .id(format!("{}/converter", receiver_config.id))
            .record()
            .build()
            .unwrap(),
    );

    let (sender, receiver) = (
        Ghash::new(sender_config, sender),
        Ghash::new(receiver_config, receiver),
    );

    (sender, receiver)
}
