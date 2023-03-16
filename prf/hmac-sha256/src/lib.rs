//! This module contains the protocol for computing TLS SHA-256 HMAC PRF using 2PC in such a way
//! that neither party learns the session keys, rather, they learn encodings of the keys which can
//! be used in subsequent computations.

pub(crate) mod circuits;
mod follower;
mod leader;

use async_trait::async_trait;

use hmac_sha256_core::SessionKeyLabels;
use mpc_aio::protocol::garble::GCError;

pub use follower::DEPRFFollower;
pub use leader::DEPRFLeader;

pub use hmac_sha256_core::{
    PRFFollowerConfig, PRFFollowerConfigBuilder, PRFFollowerConfigBuilderError, PRFLeaderConfig,
    PRFLeaderConfigBuilder, PRFLeaderConfigBuilderError, PmsLabels,
};

#[derive(Debug, thiserror::Error)]
pub enum PRFError {
    #[error("GCError: {0}")]
    GCError(#[from] GCError),
    #[error("GCFactoryError: {0}")]
    GCFactoryError(#[from] mpc_aio::protocol::garble::factory::GCFactoryError),
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("MuxerError: {0}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
}

#[async_trait]
pub trait PRFLeader {
    async fn compute_session_keys(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        pms_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError>;

    async fn compute_client_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PRFError>;

    async fn compute_server_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PRFError>;
}

#[async_trait]
pub trait PRFFollower {
    async fn compute_session_keys(
        &mut self,
        pms_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError>;

    async fn compute_client_finished_vd(&mut self) -> Result<(), PRFError>;

    async fn compute_server_finished_vd(&mut self) -> Result<(), PRFError>;
}

pub mod mock {
    use hmac_sha256_core::{PRFFollowerConfig, PRFLeaderConfig};
    use mpc_aio::protocol::garble::{
        exec::dual::mock::{MockDualExFollower, MockDualExLeader},
        factory::dual::mock::{create_mock_dualex_factory, MockDualExFactory},
    };

    pub use hmac_sha256_core::mock::*;

    use crate::{DEPRFFollower, DEPRFLeader};

    pub fn create_mock_prf_pair(
        leader_config: PRFLeaderConfig,
        follower_config: PRFFollowerConfig,
    ) -> (
        DEPRFLeader<MockDualExFactory, MockDualExLeader>,
        DEPRFFollower<MockDualExFactory, MockDualExFollower>,
    ) {
        let de_factory = create_mock_dualex_factory();

        let leader = DEPRFLeader::<MockDualExFactory, MockDualExLeader>::new(
            leader_config,
            de_factory.clone(),
        );
        let follower = DEPRFFollower::<MockDualExFactory, MockDualExFollower>::new(
            follower_config,
            de_factory,
        );

        (leader, follower)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::lock::Mutex;
    use hmac_sha256_core::{
        utils::{compute_client_finished_vd, compute_ms, compute_server_finished_vd},
        PRFFollowerConfigBuilder, PRFLeaderConfigBuilder,
    };

    use super::*;
    use mock::*;

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_prf() {
        let leader_config = PRFLeaderConfigBuilder::default()
            .id("test".to_string())
            .build()
            .unwrap();
        let follower_config = PRFFollowerConfigBuilder::default()
            .id("test".to_string())
            .build()
            .unwrap();

        let (mut leader, mut follower) = create_mock_prf_pair(leader_config, follower_config);

        let pms = [42u8; 32];
        let client_random = [69u8; 32];
        let server_random: [u8; 32] = [96u8; 32];
        let cf_hs_hash: [u8; 32] = [1u8; 32];
        let sf_hs_hash: [u8; 32] = [2u8; 32];

        let ((leader_share, follower_share), (leader_encoder, follower_encoder)) =
            create_mock_pms_labels(pms);

        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

        let ms = compute_ms(&client_random, &server_random, &pms);

        let (leader_keys, follower_keys) = tokio::try_join!(
            leader.compute_session_keys(client_random, server_random, leader_share),
            follower.compute_session_keys(follower_share)
        )
        .unwrap();

        let leader_cwk = leader_keys
            .active_cwk
            .decode(follower_keys.full_cwk.get_decoding())
            .unwrap();
        let leader_swk = leader_keys
            .active_swk
            .decode(follower_keys.full_swk.get_decoding())
            .unwrap();
        let leader_civ = leader_keys
            .active_civ
            .decode(follower_keys.full_civ.get_decoding())
            .unwrap();
        let leader_siv = leader_keys
            .active_siv
            .decode(follower_keys.full_siv.get_decoding())
            .unwrap();
        let follower_cwk = follower_keys
            .active_cwk
            .decode(leader_keys.full_cwk.get_decoding())
            .unwrap();
        let follower_swk = follower_keys
            .active_swk
            .decode(leader_keys.full_swk.get_decoding())
            .unwrap();
        let follower_civ = follower_keys
            .active_civ
            .decode(leader_keys.full_civ.get_decoding())
            .unwrap();
        let follower_siv = follower_keys
            .active_siv
            .decode(leader_keys.full_siv.get_decoding())
            .unwrap();

        assert_eq!(leader_cwk, follower_cwk);
        assert_eq!(leader_swk, follower_swk);
        assert_eq!(leader_civ, follower_civ);
        assert_eq!(leader_siv, follower_siv);

        let (leader_cf_vd, _) = tokio::try_join!(
            leader.compute_client_finished_vd(cf_hs_hash),
            follower.compute_client_finished_vd()
        )
        .unwrap();

        let expected_cf_vd = compute_client_finished_vd(ms, cf_hs_hash);
        assert_eq!(leader_cf_vd, expected_cf_vd);

        let (leader_sf_vd, _) = tokio::try_join!(
            leader.compute_server_finished_vd(sf_hs_hash),
            follower.compute_server_finished_vd()
        )
        .unwrap();

        let expected_sf_vd = compute_server_finished_vd(ms, sf_hs_hash);
        assert_eq!(leader_sf_vd, expected_sf_vd);
    }
}
