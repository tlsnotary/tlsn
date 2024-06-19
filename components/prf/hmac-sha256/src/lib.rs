//! This module contains the protocol for computing TLS SHA-256 HMAC PRF.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod prf;

pub use config::{PrfConfig, PrfConfigBuilder, PrfConfigBuilderError, Role};
pub use error::PrfError;
pub use prf::MpcPrf;

use async_trait::async_trait;

use mpz_garble::value::ValueRef;

pub(crate) static CF_LABEL: &[u8] = b"client finished";
pub(crate) static SF_LABEL: &[u8] = b"server finished";

/// Session keys computed by the PRF.
#[derive(Debug, Clone)]
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

/// PRF trait for computing TLS PRF.
#[async_trait]
pub trait Prf {
    /// Sets up the PRF.
    ///
    /// # Arguments
    ///
    /// * `pms` - The pre-master secret.
    async fn setup(&mut self, pms: ValueRef) -> Result<SessionKeys, PrfError>;

    /// Sets the client random.
    ///
    /// This must be set after calling [`Prf::setup`].
    ///
    /// Only the leader can provide the client random.
    async fn set_client_random(&mut self, client_random: Option<[u8; 32]>) -> Result<(), PrfError>;

    /// Preprocesses the PRF.
    async fn preprocess(&mut self) -> Result<(), PrfError>;

    /// Computes the client finished verify data.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    async fn compute_client_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError>;

    /// Computes the server finished verify data.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    async fn compute_server_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError>;

    /// Computes the session keys.
    ///
    /// # Arguments
    ///
    /// * `server_random` - The server random.
    async fn compute_session_keys(
        &mut self,
        server_random: [u8; 32],
    ) -> Result<SessionKeys, PrfError>;
}

#[cfg(test)]
mod tests {
    use mpz_common::executor::test_st_executor;
    use mpz_garble::{config::Role as DEAPRole, protocol::deap::DEAPThread, Decode, Memory};

    use hmac_sha256_circuits::{hmac_sha256_partial, prf, session_keys};
    use mpz_ot::ideal::ot::ideal_ot;

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
        let pms = [42u8; 32];
        let client_random = [69u8; 32];
        let server_random: [u8; 32] = [96u8; 32];
        let ms = compute_ms(pms, client_random, server_random);

        let (leader_ctx_0, follower_ctx_0) = test_st_executor(128);
        let (leader_ctx_1, follower_ctx_1) = test_st_executor(128);

        let (leader_ot_send_0, follower_ot_recv_0) = ideal_ot();
        let (follower_ot_send_0, leader_ot_recv_0) = ideal_ot();
        let (leader_ot_send_1, follower_ot_recv_1) = ideal_ot();
        let (follower_ot_send_1, leader_ot_recv_1) = ideal_ot();

        let leader_thread_0 = DEAPThread::new(
            DEAPRole::Leader,
            [0u8; 32],
            leader_ctx_0,
            leader_ot_send_0,
            leader_ot_recv_0,
        );
        let leader_thread_1 = leader_thread_0
            .new_thread(leader_ctx_1, leader_ot_send_1, leader_ot_recv_1)
            .unwrap();

        let follower_thread_0 = DEAPThread::new(
            DEAPRole::Follower,
            [0u8; 32],
            follower_ctx_0,
            follower_ot_send_0,
            follower_ot_recv_0,
        );
        let follower_thread_1 = follower_thread_0
            .new_thread(follower_ctx_1, follower_ot_send_1, follower_ot_recv_1)
            .unwrap();

        // Set up public PMS for testing.
        let leader_pms = leader_thread_0.new_public_input::<[u8; 32]>("pms").unwrap();
        let follower_pms = follower_thread_0
            .new_public_input::<[u8; 32]>("pms")
            .unwrap();

        leader_thread_0.assign(&leader_pms, pms).unwrap();
        follower_thread_0.assign(&follower_pms, pms).unwrap();

        let mut leader = MpcPrf::new(
            PrfConfig::builder().role(Role::Leader).build().unwrap(),
            leader_thread_0,
            leader_thread_1,
        );
        let mut follower = MpcPrf::new(
            PrfConfig::builder().role(Role::Follower).build().unwrap(),
            follower_thread_0,
            follower_thread_1,
        );

        futures::join!(
            async {
                leader.setup(leader_pms).await.unwrap();
                leader.set_client_random(Some(client_random)).await.unwrap();
                leader.preprocess().await.unwrap();
            },
            async {
                follower.setup(follower_pms).await.unwrap();
                follower.set_client_random(None).await.unwrap();
                follower.preprocess().await.unwrap();
            }
        );

        let (leader_session_keys, follower_session_keys) = futures::try_join!(
            leader.compute_session_keys(server_random),
            follower.compute_session_keys(server_random)
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
            async {
                leader
                    .thread_mut()
                    .decode(&[leader_cwk, leader_swk, leader_civ, leader_siv])
                    .await
            },
            async {
                follower
                    .thread_mut()
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
            leader.compute_client_finished_vd(cf_hs_hash),
            follower.compute_client_finished_vd(cf_hs_hash)
        )
        .unwrap();

        let expected_cf_vd = compute_vd(ms, b"client finished", cf_hs_hash);

        assert_eq!(cf_vd, expected_cf_vd);

        let (sf_vd, _) = futures::try_join!(
            leader.compute_server_finished_vd(sf_hs_hash),
            follower.compute_server_finished_vd(sf_hs_hash)
        )
        .unwrap();

        let expected_sf_vd = compute_vd(ms, b"server finished", sf_hs_hash);

        assert_eq!(sf_vd, expected_sf_vd);
    }
}
