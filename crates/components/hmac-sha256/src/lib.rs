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

use mpz_vm_core::memory::{binary::U8, Array};

pub(crate) static CF_LABEL: &[u8] = b"client finished";
pub(crate) static SF_LABEL: &[u8] = b"server finished";

/// Builds the circuits for the PRF.
///
/// This function can be used ahead of time to build the circuits for the PRF,
/// which at the moment is CPU and memory intensive.
pub async fn build_circuits() {
    prf::Circuits::get().await;
}

/// PRF output.
#[derive(Debug, Clone, Copy)]
pub struct PrfOutput {
    /// TLS session keys.
    pub keys: SessionKeys,
    /// Client finished verify data.
    pub cf_vd: Array<U8, 12>,
    /// Server finished verify data.
    pub sf_vd: Array<U8, 12>,
}

/// Session keys computed by the PRF.
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Client IV.
    pub client_iv: Array<U8, 4>,
    /// Server IV.
    pub server_iv: Array<U8, 4>,
}

#[cfg(test)]
mod tests {
    use mpz_common::context::test_st_context;
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};

    use hmac_sha256_circuits::{hmac_sha256_partial, prf, session_keys};
    use mpz_ot::ideal::cot::ideal_cot;
    use mpz_vm_core::{memory::correlated::Delta, prelude::*};
    use rand::{rngs::StdRng, SeedableRng};

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
        let mut rng = StdRng::seed_from_u64(0);

        let pms = [42u8; 32];
        let client_random = [69u8; 32];
        let server_random: [u8; 32] = [96u8; 32];
        let ms = compute_ms(pms, client_random, server_random);

        let (mut leader_ctx, mut follower_ctx) = test_st_context(128);

        let delta = Delta::random(&mut rng);
        let (ot_send, ot_recv) = ideal_cot(delta.into_inner());

        let mut leader_vm = Generator::new(ot_send, [0u8; 16], delta);
        let mut follower_vm = Evaluator::new(ot_recv);

        let leader_pms: Array<U8, 32> = leader_vm.alloc().unwrap();
        leader_vm.mark_public(leader_pms).unwrap();
        leader_vm.assign(leader_pms, pms).unwrap();
        leader_vm.commit(leader_pms).unwrap();

        let follower_pms: Array<U8, 32> = follower_vm.alloc().unwrap();
        follower_vm.mark_public(follower_pms).unwrap();
        follower_vm.assign(follower_pms, pms).unwrap();
        follower_vm.commit(follower_pms).unwrap();

        let mut leader = MpcPrf::new(PrfConfig::builder().role(Role::Leader).build().unwrap());
        let mut follower = MpcPrf::new(PrfConfig::builder().role(Role::Follower).build().unwrap());

        let leader_output = leader.alloc(&mut leader_vm, leader_pms).unwrap();
        let follower_output = follower.alloc(&mut follower_vm, follower_pms).unwrap();

        leader
            .set_client_random(&mut leader_vm, Some(client_random))
            .unwrap();
        follower.set_client_random(&mut follower_vm, None).unwrap();

        leader
            .set_server_random(&mut leader_vm, server_random)
            .unwrap();
        follower
            .set_server_random(&mut follower_vm, server_random)
            .unwrap();

        let leader_cwk = leader_vm
            .decode(leader_output.keys.client_write_key)
            .unwrap();
        let leader_swk = leader_vm
            .decode(leader_output.keys.server_write_key)
            .unwrap();
        let leader_civ = leader_vm.decode(leader_output.keys.client_iv).unwrap();
        let leader_siv = leader_vm.decode(leader_output.keys.server_iv).unwrap();

        let follower_cwk = follower_vm
            .decode(follower_output.keys.client_write_key)
            .unwrap();
        let follower_swk = follower_vm
            .decode(follower_output.keys.server_write_key)
            .unwrap();
        let follower_civ = follower_vm.decode(follower_output.keys.client_iv).unwrap();
        let follower_siv = follower_vm.decode(follower_output.keys.server_iv).unwrap();

        futures::join!(
            async {
                leader_vm.flush(&mut leader_ctx).await.unwrap();
                leader_vm.execute(&mut leader_ctx).await.unwrap();
                leader_vm.flush(&mut leader_ctx).await.unwrap();
            },
            async {
                follower_vm.flush(&mut follower_ctx).await.unwrap();
                follower_vm.execute(&mut follower_ctx).await.unwrap();
                follower_vm.flush(&mut follower_ctx).await.unwrap();
            }
        );

        let leader_cwk = leader_cwk.await.unwrap();
        let leader_swk = leader_swk.await.unwrap();
        let leader_civ = leader_civ.await.unwrap();
        let leader_siv = leader_siv.await.unwrap();

        let follower_cwk = follower_cwk.await.unwrap();
        let follower_swk = follower_swk.await.unwrap();
        let follower_civ = follower_civ.await.unwrap();
        let follower_siv = follower_siv.await.unwrap();

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

        leader.set_cf_hash(&mut leader_vm, cf_hs_hash).unwrap();
        leader.set_sf_hash(&mut leader_vm, sf_hs_hash).unwrap();

        follower.set_cf_hash(&mut follower_vm, cf_hs_hash).unwrap();
        follower.set_sf_hash(&mut follower_vm, sf_hs_hash).unwrap();

        let leader_cf_vd = leader_vm.decode(leader_output.cf_vd).unwrap();
        let leader_sf_vd = leader_vm.decode(leader_output.sf_vd).unwrap();

        let follower_cf_vd = follower_vm.decode(follower_output.cf_vd).unwrap();
        let follower_sf_vd = follower_vm.decode(follower_output.sf_vd).unwrap();

        futures::join!(
            async {
                leader_vm.flush(&mut leader_ctx).await.unwrap();
                leader_vm.execute(&mut leader_ctx).await.unwrap();
                leader_vm.flush(&mut leader_ctx).await.unwrap();
            },
            async {
                follower_vm.flush(&mut follower_ctx).await.unwrap();
                follower_vm.execute(&mut follower_ctx).await.unwrap();
                follower_vm.flush(&mut follower_ctx).await.unwrap();
            }
        );

        let leader_cf_vd = leader_cf_vd.await.unwrap();
        let leader_sf_vd = leader_sf_vd.await.unwrap();

        let follower_cf_vd = follower_cf_vd.await.unwrap();
        let follower_sf_vd = follower_sf_vd.await.unwrap();

        let expected_cf_vd = compute_vd(ms, b"client finished", cf_hs_hash);
        let expected_sf_vd = compute_vd(ms, b"server finished", sf_hs_hash);

        assert_eq!(leader_cf_vd, expected_cf_vd);
        assert_eq!(leader_sf_vd, expected_sf_vd);
        assert_eq!(follower_cf_vd, expected_cf_vd);
        assert_eq!(follower_sf_vd, expected_sf_vd);
    }
}
