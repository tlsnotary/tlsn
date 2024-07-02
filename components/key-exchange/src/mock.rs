//! This module provides mock types for key exchange leader and follower and a function to create
//! such a pair.

use crate::{KeyExchangeConfig, MpcKeyExchange, Role};

use mpz_common::executor::{test_st_executor, STExecutor};
use mpz_garble::{Decode, Execute, Memory};
use mpz_share_conversion::ideal::{ideal_share_converter, IdealShareConverter};
use serio::channel::MemoryDuplex;

/// A mock key exchange instance.
pub type MockKeyExchange<E> =
    MpcKeyExchange<STExecutor<MemoryDuplex>, IdealShareConverter, IdealShareConverter, E>;

/// Creates a mock pair of key exchange leader and follower.
pub fn create_mock_key_exchange_pair<E: Memory + Execute + Decode + Send>(
    leader_executor: E,
    follower_executor: E,
) -> (MockKeyExchange<E>, MockKeyExchange<E>) {
    let (leader_ctx, follower_ctx) = test_st_executor(8);
    let (leader_converter_0, follower_converter_0) = ideal_share_converter();
    let (leader_converter_1, follower_converter_1) = ideal_share_converter();

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
        leader_ctx,
        leader_converter_0,
        leader_converter_1,
        leader_executor,
    );

    let follower = MpcKeyExchange::new(
        key_exchange_config_follower,
        follower_ctx,
        follower_converter_0,
        follower_converter_1,
        follower_executor,
    );

    (leader, follower)
}

#[cfg(test)]
mod tests {
    use mpz_garble::protocol::deap::mock::create_mock_deap_vm;

    use crate::KeyExchange;

    use super::*;

    #[test]
    fn test_mock_is_ke() {
        let (leader_vm, follower_vm) = create_mock_deap_vm();
        let (leader, follower) = create_mock_key_exchange_pair(leader_vm, follower_vm);

        fn is_key_exchange<T: KeyExchange>(_: T) {}

        is_key_exchange(leader);
        is_key_exchange(follower);
    }
}
