//! This module provides mock types for key exchange leader and follower and a
//! function to create such a pair.

use crate::{KeyExchangeConfig, MpcKeyExchange, Role};
use mpz_core::Block;
use mpz_fields::p256::P256;
use mpz_share_conversion::ideal::{
    ideal_share_convert, IdealShareConvertReceiver, IdealShareConvertSender,
};

/// A mock key exchange instance.
pub type MockKeyExchange =
    MpcKeyExchange<IdealShareConvertSender<P256>, IdealShareConvertReceiver<P256>>;

/// Creates a mock pair of key exchange leader and follower.
pub fn create_mock_key_exchange_pair() -> (MockKeyExchange, MockKeyExchange) {
    let (leader_converter_0, follower_converter_0) = ideal_share_convert(Block::ZERO);
    let (follower_converter_1, leader_converter_1) = ideal_share_convert(Block::ZERO);

    let key_exchange_config_leader = KeyExchangeConfig::builder()
        .role(Role::Leader)
        .build()
        .unwrap();

    let key_exchange_config_follower = KeyExchangeConfig::builder()
        .role(Role::Follower)
        .build()
        .unwrap();

    let leader = MpcKeyExchange::new(
        key_exchange_config_leader,
        leader_converter_0,
        leader_converter_1,
    );

    let follower = MpcKeyExchange::new(
        key_exchange_config_follower,
        follower_converter_1,
        follower_converter_0,
    );

    (leader, follower)
}

#[cfg(test)]
mod tests {
    use mpz_common::executor::TestSTExecutor;
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_ot::ideal::cot::{IdealCOTReceiver, IdealCOTSender};

    use super::*;
    use crate::KeyExchange;

    #[test]
    fn test_mock_is_ke() {
        let (leader, follower) = create_mock_key_exchange_pair();

        fn is_key_exchange<T: KeyExchange<V>, Ctx, V>(_: T) {}

        is_key_exchange::<
            MpcKeyExchange<IdealShareConvertSender<P256>, IdealShareConvertReceiver<P256>>,
            TestSTExecutor,
            Generator<IdealCOTSender>,
        >(leader);

        is_key_exchange::<
            MpcKeyExchange<IdealShareConvertSender<P256>, IdealShareConvertReceiver<P256>>,
            TestSTExecutor,
            Evaluator<IdealCOTReceiver>,
        >(follower);
    }
}
