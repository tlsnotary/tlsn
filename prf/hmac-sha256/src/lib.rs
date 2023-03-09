//! This module contains the protocol for computing TLS SHA-256 HMAC PRF using 2PC in such a way
//! that neither party learns the session keys, rather they learn respective shares of the keys.
//!
//! For a more comprehensive explanation of this protocol see our [documentation](https://tlsnotary.github.io/docs-mdbook)
//!
//! To save some compute and bandwidth, the PRF can be broken down into smaller units where some can be
//! computed without using 2PC.
//!
//! To elaborate, recall how HMAC is computed (assuming |k| <= block size):
//!
//! HMAC(k, m) = H((k ⊕ opad) | H((k ⊕ ipad) | m))
//!
//! Notice that both H(k ⊕ opad) and H(k ⊕ ipad) can be computed separately prior to finalization. In this
//! codebase we name these units as such:
//! - Outer hash state: H(k ⊕ opad)
//! - Inner hash state: H(k ⊕ ipad)
//! - Inner hash: H((k ⊕ ipad) | m)
//!
//! In TLS, the master secret is computed like so:
//!
//! ```text
//! seed = "master secret" | client_random | server_random
//! a0 = seed
//! a1 = HMAC(pms, a0)
//! a2 = HMAC(pms, a1)
//! p1 = HMAC(pms, a1 | seed)
//! p2 = HMAC(pms, a2 | seed)
//! ms = (p1 | p2)[:48]
//! ```
//!
//! Notice that in each step the key, in this case PMS, is constant. Thus both the outer and inner hash state can be reused
//! for each step.
//!
//! Here is a small illustration of what this looks like:
//!
//! ```text
//! +------------+                                              +------------+
//! |            |                                              |            |
//! |   Leader   |                                              |  Follower  |
//! |            |                                              |            |
//! +-----+------+                                              +-----+------+
//!       |                                                           |
//!       |  PMS SHARE             +-----------+           PMS SHARE  |
//!       +----------------------> |           | <--------------------+
//!       |                        |    2PC    |                      |
//!       | <----------------------+           +--------------------> |
//!       |          INNER HASH    +-----------+  OUTER HASH          |
//!       |          STATE                        STATE               |
//!       |          H(PMS ⊕ ipad)                H(PMS ⊕ opad)       |
//!       |                                                           |
//!
//! H((PMS ⊕ ipad)|seed) ------------------> H((PMS ⊕ opad))|H((PMS ⊕ ipad)|seed))=a1
//!
//!                                                               a1  |
//!         <---------------------------------------------------------+
//! ```
//!
//! Following, the master secret is expanded to the session keys like so:
//!
//! ```text
//! seed = "key expansion" | server_random | client_random
//! a0 = seed
//! a1 = HMAC(ms, a0)
//! a2 = HMAC(ms, a1)
//! p1 = HMAC(ms, a1 | seed)
//! p2 = HMAC(ms, a2 | seed)
//! ek = (p1 | p2)[:40]
//! cwk = ek[:16]
//! swk = ek[16:32]
//! civ = ek[32:36]
//! siv = ek[36:40]
//! ```

pub(crate) mod circuits;
mod follower;
mod leader;

use async_trait::async_trait;

use hmac_sha256_core::SessionKeyLabels;
use mpc_aio::protocol::garble::GCError;
use utils_aio::Channel;

pub use follower::DEPRFFollower;
pub use leader::DEPRFLeader;

pub use hmac_sha256_core::{
    msgs::PRFMessage, PRFFollowerConfig, PRFFollowerConfigBuilder, PRFFollowerConfigBuilderError,
    PRFLeaderConfig, PRFLeaderConfigBuilder, PRFLeaderConfigBuilderError, PmsLabels,
};

pub type PRFChannel = Box<dyn Channel<PRFMessage, Error = std::io::Error>>;

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
    #[error("Unexpected Message: {0:?}")]
    UnexpectedMessage(PRFMessage),
}

#[async_trait]
pub trait PRFLeader {
    async fn compute_session_keys(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        pms_share_labels: PmsLabels,
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
        pms_share_labels: PmsLabels,
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
    use utils_aio::duplex::DuplexChannel;

    pub use hmac_sha256_core::mock::*;

    use crate::{DEPRFFollower, DEPRFLeader};

    pub fn create_mock_prf_pair(
        leader_config: PRFLeaderConfig,
        follower_config: PRFFollowerConfig,
    ) -> (
        DEPRFLeader<MockDualExFactory, MockDualExLeader>,
        DEPRFFollower<MockDualExFactory, MockDualExFollower>,
    ) {
        let (leader_channel, follower_channel) = DuplexChannel::new();
        let de_factory = create_mock_dualex_factory();

        let leader = DEPRFLeader::<MockDualExFactory, MockDualExLeader>::new(
            leader_config,
            Box::new(leader_channel),
            de_factory.clone(),
        );
        let follower = DEPRFFollower::<MockDualExFactory, MockDualExFollower>::new(
            follower_config,
            Box::new(follower_channel),
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
        utils::{
            compute_client_finished_vd, compute_ms, compute_server_finished_vd, key_expansion_tls12,
        },
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

        let ((leader_share, follower_share), (leader_encoder, follower_encoder)) =
            create_mock_pms_labels(pms);

        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

        let ms = compute_ms(&client_random, &server_random, &pms);

        let (leader_keys, follower_keys) = futures::join!(
            leader.compute_session_keys(client_random, server_random, leader_share),
            follower.compute_session_keys(follower_share)
        );

        let leader_keys = leader_keys.unwrap();
        let follower_keys = follower_keys.unwrap();

        let leader_cwk = leader_keys
            .active_cwk()
            .decode(follower_keys.full_cwk().get_decoding())
            .unwrap();
        let leader_swk = leader_keys
            .active_swk()
            .decode(follower_keys.full_swk().get_decoding())
            .unwrap();
        let leader_civ = leader_keys
            .active_civ()
            .decode(follower_keys.full_civ().get_decoding())
            .unwrap();
        let leader_siv = leader_keys
            .active_siv()
            .decode(follower_keys.full_siv().get_decoding())
            .unwrap();
        let follower_cwk = follower_keys
            .active_cwk()
            .decode(leader_keys.full_cwk().get_decoding())
            .unwrap();
        let follower_swk = follower_keys
            .active_swk()
            .decode(leader_keys.full_swk().get_decoding())
            .unwrap();
        let follower_civ = follower_keys
            .active_civ()
            .decode(leader_keys.full_civ().get_decoding())
            .unwrap();
        let follower_siv = follower_keys
            .active_siv()
            .decode(leader_keys.full_siv().get_decoding())
            .unwrap();

        assert_eq!(leader_cwk, follower_cwk);
        assert_eq!(leader_swk, follower_swk);
        assert_eq!(leader_civ, follower_civ);
        assert_eq!(leader_siv, follower_siv);

        let cwk = leader_cwk
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .collect::<Vec<u8>>();

        let swk = leader_swk
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .collect::<Vec<u8>>();

        let civ = leader_civ
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .collect::<Vec<u8>>();

        let siv = leader_siv
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .collect::<Vec<u8>>();

        let (expected_cwk, expected_swk, expected_civ, expected_siv) =
            key_expansion_tls12(&client_random, &server_random, &pms);

        assert_eq!(cwk, expected_cwk);
        assert_eq!(swk, expected_swk);
        assert_eq!(civ, expected_civ);
        assert_eq!(siv, expected_siv);

        let (leader_cf_vd_result, follower_cf_vd_result) = futures::join!(
            leader.compute_client_finished_vd([1u8; 32]),
            follower.compute_client_finished_vd()
        );

        let leader_cf_vd = leader_cf_vd_result.unwrap();
        _ = follower_cf_vd_result.unwrap();

        let expected_cf_vd = compute_client_finished_vd(ms, [1u8; 32]);
        assert_eq!(leader_cf_vd, expected_cf_vd);

        let (leader_sf_vd_result, follower_sf_vd_result) = futures::join!(
            leader.compute_server_finished_vd([2u8; 32]),
            follower.compute_server_finished_vd()
        );

        let leader_sf_vd = leader_sf_vd_result.unwrap();
        _ = follower_sf_vd_result.unwrap();

        let expected_sf_vd = compute_server_finished_vd(ms, [2u8; 32]);
        assert_eq!(leader_sf_vd, expected_sf_vd);
    }
}
