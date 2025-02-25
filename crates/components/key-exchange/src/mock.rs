//! This module provides mock types for key exchange leader and follower and a
//! function to create such a pair.

use crate::{MpcKeyExchange, Role};
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

    let leader = MpcKeyExchange::new(Role::Leader, leader_converter_0, leader_converter_1);

    let follower = MpcKeyExchange::new(Role::Follower, follower_converter_1, follower_converter_0);

    (leader, follower)
}

#[cfg(test)]
mod tests {
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_ot::ideal::cot::{IdealCOTReceiver, IdealCOTSender};

    use super::*;
    use crate::KeyExchange;

    #[test]
    fn test_mock_is_ke() {
        let (leader, follower) = create_mock_key_exchange_pair();

        fn is_key_exchange<T: KeyExchange, V>(_: T) {}

        is_key_exchange::<
            MpcKeyExchange<IdealShareConvertSender<P256>, IdealShareConvertReceiver<P256>>,
            Generator<IdealCOTSender>,
        >(leader);

        is_key_exchange::<
            MpcKeyExchange<IdealShareConvertSender<P256>, IdealShareConvertReceiver<P256>>,
            Evaluator<IdealCOTReceiver>,
        >(follower);
    }
}
