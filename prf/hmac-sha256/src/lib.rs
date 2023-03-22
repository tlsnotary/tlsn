//! This module contains the protocol for computing TLS SHA-256 HMAC PRF using 2PC in such a way
//! that neither party learns the session keys, rather, they learn encodings of the keys which can
//! be used in subsequent computations.

pub(crate) mod circuits;
mod follower;
mod leader;

use async_trait::async_trait;

use hmac_sha256_core::{MasterSecretStateLabels, SessionKeyLabels};
use mpc_garble::GCError;

pub use follower::PRFFollower;
pub use leader::PRFLeader;

pub use hmac_sha256_core::{
    PRFFollowerConfig, PRFFollowerConfigBuilder, PRFFollowerConfigBuilderError, PRFLeaderConfig,
    PRFLeaderConfigBuilder, PRFLeaderConfigBuilderError, PmsLabels,
};

#[derive(Debug, Clone)]
pub enum State {
    SessionKeys,
    ClientFinished {
        ms_hash_state_labels: MasterSecretStateLabels,
    },
    ServerFinished {
        ms_hash_state_labels: MasterSecretStateLabels,
    },
    Complete,
    Error,
}

#[derive(Debug, thiserror::Error)]
pub enum PRFError {
    #[error("GCError: {0}")]
    GCError(#[from] GCError),
    #[error("GCFactoryError: {0}")]
    GCFactoryError(#[from] mpc_garble::factory::GCFactoryError),
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("MuxerError: {0}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error("Encoder not set")]
    EncoderNotSet,
    #[error("Invalid state: {0:?}")]
    InvalidState(State),
}

#[async_trait]
pub trait PRFLead {
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
pub trait PRFFollow {
    async fn compute_session_keys(
        &mut self,
        pms_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError>;

    async fn compute_client_finished_vd(&mut self) -> Result<(), PRFError>;

    async fn compute_server_finished_vd(&mut self) -> Result<(), PRFError>;
}

pub mod mock {
    use hmac_sha256_core::{PRFFollowerConfig, PRFLeaderConfig};
    use mpc_garble::{
        exec::dual::mock::{MockDualExFollower, MockDualExLeader},
        factory::dual::mock::{create_mock_dualex_factory, MockDualExFactory},
    };

    pub use hmac_sha256_core::mock::*;

    use crate::{PRFFollower, PRFLeader};

    pub fn create_mock_prf_pair(
        leader_config: PRFLeaderConfig,
        follower_config: PRFFollowerConfig,
    ) -> (
        PRFLeader<MockDualExFactory, MockDualExLeader>,
        PRFFollower<MockDualExFactory, MockDualExFollower>,
    ) {
        let de_factory = create_mock_dualex_factory();

        let leader = PRFLeader::<MockDualExFactory, MockDualExLeader>::new(
            leader_config,
            de_factory.clone(),
        );
        let follower =
            PRFFollower::<MockDualExFactory, MockDualExFollower>::new(follower_config, de_factory);

        (leader, follower)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::lock::Mutex;
    use hmac_sha256_core::{PRFFollowerConfigBuilder, PRFLeaderConfigBuilder};

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
        let seed = client_random
            .iter()
            .chain(&server_random)
            .copied()
            .collect::<Vec<_>>();
        let ms = hmac_sha256_utils::prf(&pms, b"master secret", &seed, 48);

        let ((leader_share, follower_share), (leader_encoder, follower_encoder)) =
            create_mock_pms_labels(pms);

        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

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

        let expected_cf_vd = hmac_sha256_utils::prf(&ms, b"client finished", &cf_hs_hash, 12);
        assert_eq!(leader_cf_vd.to_vec(), expected_cf_vd);

        let (leader_sf_vd, _) = tokio::try_join!(
            leader.compute_server_finished_vd(sf_hs_hash),
            follower.compute_server_finished_vd()
        )
        .unwrap();

        let expected_sf_vd = hmac_sha256_utils::prf(&ms, b"server finished", &sf_hs_hash, 12);
        assert_eq!(leader_sf_vd.to_vec(), expected_sf_vd);
    }
}
