//! This module contains the protocol for computing TLS SHA-256 HMAC PRF.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod prf;

pub use prf::MpcPrf;

use async_trait::async_trait;

use mpc_garble::ValueRef;
use prf::State;

/// Session keys computed by the PRF.
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: ValueRef,
    /// Server write key.
    pub server_write_key: ValueRef,
    /// Client IV.
    pub client_iv: ValueRef,
    /// Server IV.
    pub server_iv: ValueRef,
}

/// Errors that can occur during PRF computation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum PrfError {
    #[error(transparent)]
    MemoryError(#[from] mpc_garble::MemoryError),
    #[error(transparent)]
    ExecutionError(#[from] mpc_garble::ExecutionError),
    #[error(transparent)]
    DecodeError(#[from] mpc_garble::DecodeError),
    #[error("role error: {0:?}")]
    RoleError(String),
    #[error("Invalid state: {0:?}")]
    InvalidState(State),
}

/// PRF trait for computing TLS PRF.
#[async_trait]
pub trait Prf {
    /// Computes the session keys using the provided client random, server random and PMS.
    async fn compute_session_keys_private(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        pms: ValueRef,
    ) -> Result<SessionKeys, PrfError>;

    /// Computes the client finished verify data using the provided handshake hash.
    async fn compute_client_finished_vd_private(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError>;

    /// Computes the server finished verify data using the provided handshake hash.
    async fn compute_server_finished_vd_private(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError>;

    /// Computes the session keys using randoms provided by the other party.
    async fn compute_session_keys_blind(&mut self, pms: ValueRef) -> Result<SessionKeys, PrfError>;

    /// Computes the client finished verify data using the handshake hash provided by the other party.
    async fn compute_client_finished_vd_blind(&mut self) -> Result<(), PrfError>;

    /// Computes the server finished verify data using the handshake hash provided by the other party.
    async fn compute_server_finished_vd_blind(&mut self) -> Result<(), PrfError>;
}

#[cfg(test)]
mod tests {
    use mpc_garble::{protocol::deap::mock::create_mock_deap_vm, Decode, Memory, Vm};

    use hmac_sha256_circuits::{hmac_sha256_partial, prf, session_keys};

    use super::*;

    fn compute_ms(pms: [u8; 32], client_random: [u8; 32], server_random: [u8; 32]) -> [u8; 48] {
        let (outer_state, inner_state) = hmac_sha256_partial(&pms);
        let seed = client_random
            .iter()
            .chain(&server_random)
            .copied()
            .collect::<Vec<_>>();
        let ms = prf(outer_state, inner_state, &seed, b"master secret", 48);
        ms.try_into().unwrap()
    }

    fn compute_vd(ms: [u8; 48], label: &[u8], hs_hash: [u8; 32]) -> [u8; 12] {
        let (outer_state, inner_state) = hmac_sha256_partial(&ms);
        let vd = prf(outer_state, inner_state, &hs_hash, label, 12);
        vd.try_into().unwrap()
    }

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_prf() {
        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test").await;

        let mut leader_test_thread = leader_vm.new_thread("test").await.unwrap();
        let mut follower_test_thread = follower_vm.new_thread("test").await.unwrap();

        let mut leader = MpcPrf::new(leader_vm.new_thread("prf").await.unwrap());
        let mut follower = MpcPrf::new(follower_vm.new_thread("prf").await.unwrap());

        let pms = [42u8; 32];
        let client_random = [69u8; 32];
        let server_random: [u8; 32] = [96u8; 32];
        let ms = compute_ms(pms, client_random, server_random);

        // Setup public PMS for testing
        let leader_pms = leader_test_thread.new_public_input("pms", pms).unwrap();
        let follower_pms = follower_test_thread.new_public_input("pms", pms).unwrap();

        let (leader_session_keys, follower_session_keys) = futures::try_join!(
            leader.compute_session_keys_private(client_random, server_random, leader_pms),
            follower.compute_session_keys_blind(follower_pms)
        )
        .unwrap();

        let SessionKeys {
            client_write_key: leader_cwk,
            server_write_key: leader_swk,
            client_iv: leader_civ,
            server_iv: leader_siv,
        } = leader_session_keys;

        let SessionKeys {
            client_write_key: follower_cwk,
            server_write_key: follower_swk,
            client_iv: follower_civ,
            server_iv: follower_siv,
        } = follower_session_keys;

        // Decode session keys
        let (leader_session_keys, follower_session_keys) = futures::try_join!(
            async move {
                leader_test_thread
                    .decode(&[leader_cwk, leader_swk, leader_civ, leader_siv])
                    .await
            },
            async move {
                follower_test_thread
                    .decode(&[follower_cwk, follower_swk, follower_civ, follower_siv])
                    .await
            }
        )
        .unwrap();

        let leader_cwk: [u8; 16] = leader_session_keys[0].clone().try_into().unwrap();
        let leader_swk: [u8; 16] = leader_session_keys[1].clone().try_into().unwrap();
        let leader_civ: [u8; 4] = leader_session_keys[2].clone().try_into().unwrap();
        let leader_siv: [u8; 4] = leader_session_keys[3].clone().try_into().unwrap();

        let follower_cwk: [u8; 16] = follower_session_keys[0].clone().try_into().unwrap();
        let follower_swk: [u8; 16] = follower_session_keys[1].clone().try_into().unwrap();
        let follower_civ: [u8; 4] = follower_session_keys[2].clone().try_into().unwrap();
        let follower_siv: [u8; 4] = follower_session_keys[3].clone().try_into().unwrap();

        let (expected_cwk, expected_swk, expected_civ, expected_siv) =
            session_keys(pms, client_random, server_random);

        assert_eq!(leader_cwk, expected_cwk);
        assert_eq!(leader_swk, expected_swk);
        assert_eq!(leader_civ, expected_civ);
        assert_eq!(leader_siv, expected_siv);

        assert_eq!(follower_cwk, expected_cwk);
        assert_eq!(follower_swk, expected_swk);
        assert_eq!(follower_civ, expected_civ);
        assert_eq!(follower_siv, expected_siv);

        let cf_hs_hash = [1u8; 32];
        let sf_hs_hash = [2u8; 32];

        let (cf_vd, _) = futures::try_join!(
            leader.compute_client_finished_vd_private(cf_hs_hash),
            follower.compute_client_finished_vd_blind()
        )
        .unwrap();

        let expected_cf_vd = compute_vd(ms, b"client finished", cf_hs_hash);

        assert_eq!(cf_vd, expected_cf_vd);

        let (sf_vd, _) = futures::try_join!(
            leader.compute_server_finished_vd_private(sf_hs_hash),
            follower.compute_server_finished_vd_blind()
        )
        .unwrap();

        let expected_sf_vd = compute_vd(ms, b"server finished", sf_hs_hash);

        assert_eq!(sf_vd, expected_sf_vd);
    }
}
