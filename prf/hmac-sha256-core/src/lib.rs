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

mod config;
mod follower;
mod leader;
pub mod msgs;
pub mod sha;
pub mod utils;

pub use crate::msgs::PRFMessage;
pub use config::{
    PRFFollowerConfig, PRFFollowerConfigBuilder, PRFFollowerConfigBuilderError, PRFLeaderConfig,
    PRFLeaderConfigBuilder, PRFLeaderConfigBuilderError, Role,
};
pub use follower::{state as follower_state, PRFFollower};
pub use leader::{state as leader_state, PRFLeader};

use mpc_circuits::Circuit;
use mpc_core::garble::{ActiveLabels, FullLabels};
use once_cell::sync::Lazy;
use std::sync::Arc;

pub static PMS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/premaster_secret.bin")).unwrap()
});
pub static MS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/master_secret.bin")).unwrap()
});
pub static SESSION_KEYS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/session_keys.bin")).unwrap()
});
pub static CF_VD: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/cf_verify_data.bin")).unwrap()
});
pub static SF_VD: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/sf_verify_data.bin")).unwrap()
});

#[derive(Debug, Clone)]
pub struct PmsLabels {
    full: FullLabels,
    active: ActiveLabels,
}

impl PmsLabels {
    pub fn new(full: FullLabels, active: ActiveLabels) -> Self {
        Self { full, active }
    }

    pub fn full_labels(&self) -> &FullLabels {
        &self.full
    }

    pub fn active_labels(&self) -> &ActiveLabels {
        &self.active
    }
}

#[derive(Debug, Clone)]
pub struct MasterSecretStateLabels {
    full_outer_hash_state: FullLabels,
    full_inner_hash_state: FullLabels,
    active_outer_hash_state: ActiveLabels,
    active_inner_hash_state: ActiveLabels,
}

impl MasterSecretStateLabels {
    pub fn new(
        full_outer_state: FullLabels,
        full_inner_state: FullLabels,
        active_outer_state: ActiveLabels,
        active_inner_state: ActiveLabels,
    ) -> Self {
        Self {
            full_outer_hash_state: full_outer_state,
            full_inner_hash_state: full_inner_state,
            active_outer_hash_state: active_outer_state,
            active_inner_hash_state: active_inner_state,
        }
    }

    pub fn full_outer_hash_state(&self) -> &FullLabels {
        &self.full_outer_hash_state
    }

    pub fn full_inner_hash_state(&self) -> &FullLabels {
        &self.full_inner_hash_state
    }

    pub fn active_outer_hash_state(&self) -> &ActiveLabels {
        &self.active_outer_hash_state
    }

    pub fn active_inner_hash_state(&self) -> &ActiveLabels {
        &self.active_inner_hash_state
    }
}

#[derive(Debug, Clone)]
pub struct SessionKeyLabels {
    full_cwk: FullLabels,
    full_swk: FullLabels,
    full_civ: FullLabels,
    full_siv: FullLabels,
    active_cwk: ActiveLabels,
    active_swk: ActiveLabels,
    active_civ: ActiveLabels,
    active_siv: ActiveLabels,
}

impl SessionKeyLabels {
    pub fn new(
        full_cwk: FullLabels,
        full_swk: FullLabels,
        full_civ: FullLabels,
        full_siv: FullLabels,
        active_cwk: ActiveLabels,
        active_swk: ActiveLabels,
        active_civ: ActiveLabels,
        active_siv: ActiveLabels,
    ) -> Self {
        Self {
            full_cwk,
            full_swk,
            full_civ,
            full_siv,
            active_cwk,
            active_swk,
            active_civ,
            active_siv,
        }
    }

    pub fn full_cwk(&self) -> &FullLabels {
        &self.full_cwk
    }

    pub fn full_swk(&self) -> &FullLabels {
        &self.full_swk
    }

    pub fn full_civ(&self) -> &FullLabels {
        &self.full_civ
    }

    pub fn full_siv(&self) -> &FullLabels {
        &self.full_siv
    }

    pub fn active_cwk(&self) -> &ActiveLabels {
        &self.active_cwk
    }

    pub fn active_swk(&self) -> &ActiveLabels {
        &self.active_swk
    }

    pub fn active_civ(&self) -> &ActiveLabels {
        &self.active_civ
    }

    pub fn active_siv(&self) -> &ActiveLabels {
        &self.active_siv
    }
}

pub mod mock {
    use mpc_circuits::BitOrder;
    use mpc_core::garble::{ChaChaEncoder, Encoder};

    use crate::sha::partial_sha256_digest;

    use super::*;

    pub fn create_mock_pms_labels(
        pms: [u8; 32],
    ) -> ((PmsLabels, PmsLabels), (ChaChaEncoder, ChaChaEncoder)) {
        let mut leader_encoder = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);
        let mut follower_encoder = ChaChaEncoder::new([1u8; 32], BitOrder::Msb0);

        let pms = pms.to_vec();

        let leader_delta = leader_encoder.get_delta();
        let follower_delta = follower_encoder.get_delta();

        let leader_rng = leader_encoder.get_stream(0);
        let follower_rng = follower_encoder.get_stream(0);

        let leader_full_labels = FullLabels::generate(leader_rng, 256, Some(leader_delta));
        let follower_full_labels = FullLabels::generate(follower_rng, 256, Some(follower_delta));

        let leader_active_labels = leader_full_labels
            .select(&pms.clone().into(), BitOrder::Msb0)
            .unwrap();
        let follower_active_labels = follower_full_labels
            .select(&pms.into(), BitOrder::Msb0)
            .unwrap();

        let leader_pms_labels = PmsLabels {
            full: leader_full_labels,
            active: follower_active_labels,
        };

        let follower_pms_labels = PmsLabels {
            full: follower_full_labels,
            active: leader_active_labels,
        };

        (
            (leader_pms_labels, follower_pms_labels),
            (leader_encoder, follower_encoder),
        )
    }

    pub fn create_mock_ms_state_labels(
        ms: [u8; 48],
    ) -> (
        (MasterSecretStateLabels, MasterSecretStateLabels),
        (ChaChaEncoder, ChaChaEncoder),
    ) {
        let mut leader_encoder = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);
        let mut follower_encoder = ChaChaEncoder::new([1u8; 32], BitOrder::Msb0);

        let mut ms_zeropadded = [0u8; 64];
        ms_zeropadded[0..48].copy_from_slice(&ms);

        let ms_opad = ms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let ms_ipad = ms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        let outer_hash_state = partial_sha256_digest(&ms_opad);
        let inner_hash_state = partial_sha256_digest(&ms_ipad);

        let outer_hash_state = outer_hash_state
            .iter()
            .map(|chunk| chunk.to_le_bytes())
            .rev()
            .flatten()
            .collect::<Vec<u8>>();
        let inner_hash_state = inner_hash_state
            .iter()
            .map(|chunk| chunk.to_le_bytes())
            .rev()
            .flatten()
            .collect::<Vec<u8>>();

        let leader_delta = leader_encoder.get_delta();
        let follower_delta = follower_encoder.get_delta();

        let leader_rng = leader_encoder.get_stream(0);
        let follower_rng = follower_encoder.get_stream(0);

        let leader_full_outer_hash_state_labels =
            FullLabels::generate(leader_rng, 256, Some(leader_delta));
        let leader_full_inner_hash_state_labels =
            FullLabels::generate(follower_rng, 256, Some(leader_delta));

        let follower_full_outer_hash_state_labels =
            FullLabels::generate(leader_rng, 256, Some(follower_delta));
        let follower_full_inner_hash_state_labels =
            FullLabels::generate(follower_rng, 256, Some(follower_delta));

        let leader_active_outer_hash_state_labels = leader_full_outer_hash_state_labels
            .select(&outer_hash_state.clone().into(), BitOrder::Msb0)
            .unwrap();
        let leader_active_inner_hash_state_labels = leader_full_inner_hash_state_labels
            .select(&inner_hash_state.clone().into(), BitOrder::Msb0)
            .unwrap();

        let follower_active_outer_hash_state_labels = follower_full_outer_hash_state_labels
            .select(&outer_hash_state.into(), BitOrder::Msb0)
            .unwrap();
        let follower_active_inner_hash_state_labels = follower_full_inner_hash_state_labels
            .select(&inner_hash_state.into(), BitOrder::Msb0)
            .unwrap();

        let leader_ms_state_labels = MasterSecretStateLabels {
            full_outer_hash_state: leader_full_outer_hash_state_labels,
            full_inner_hash_state: leader_full_inner_hash_state_labels,
            active_outer_hash_state: follower_active_outer_hash_state_labels,
            active_inner_hash_state: follower_active_inner_hash_state_labels,
        };

        let follower_ms_state_labels = MasterSecretStateLabels {
            full_outer_hash_state: follower_full_outer_hash_state_labels,
            full_inner_hash_state: follower_full_inner_hash_state_labels,
            active_outer_hash_state: leader_active_outer_hash_state_labels,
            active_inner_hash_state: leader_active_inner_hash_state_labels,
        };

        (
            (leader_ms_state_labels, follower_ms_state_labels),
            (leader_encoder, follower_encoder),
        )
    }
}

#[cfg(test)]
mod tests {
    use self::utils::*;
    use super::*;
    use hex;
    use sha::{finalize_sha256_digest, partial_sha256_digest};

    #[test]
    fn test_prf() {
        let client_random = [0x01_u8; 32];
        let server_random = [0x02_u8; 32];
        let pms = [0x03_u8; 32];

        let (ipad, opad) = generate_hmac_pads(&pms);

        // H(pms xor ipad)
        let inner_hash_state = partial_sha256_digest(&ipad);
        // H(pms xor opad)
        let outer_hash_state = partial_sha256_digest(&opad);

        let leader = PRFLeader::new();
        let follower = PRFFollower::new();

        let (leader_msg, leader) = leader.next(client_random, server_random, inner_hash_state);
        let (follower_msg, follower) = follower.next(outer_hash_state, leader_msg);

        // H((pms xor opad) || H((pms xor ipad) || seed))
        let a1 = follower_msg.a1;
        assert_eq!(
            &a1,
            &hmac_sha256(&pms, &seed_ms(&client_random, &server_random))
        );

        let (leader_msg, leader) = leader.next(follower_msg);
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = follower_msg.a2;
        assert_eq!(&a2, &hmac_sha256(&pms, &a1));

        let (leader_msg, leader) = leader.next(follower_msg);
        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        let follower = follower.next(leader_msg);

        // a1 || seed
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed_ms(&client_random, &server_random));
        // H((pms xor opad) || H((pms xor ipad) || a1 || seed))
        let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &a1_seed);
        assert_eq!(inner_hash, leader.p1_inner_hash());

        let leader = leader.next();

        // a2 || seed
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed_ms(&client_random, &server_random));
        let p2 = hmac_sha256(&pms, &a2_seed);
        assert_eq!(follower.p2(), p2);

        let follower = follower.next();

        let p1 = finalize_sha256_digest(outer_hash_state, 64, &inner_hash);

        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..48].copy_from_slice(&p2[..16]);

        let (ipad, opad) = generate_hmac_pads(&ms);

        // H(ms xor ipad)
        let inner_hash_state = partial_sha256_digest(&ipad);
        // H(ms xor opad)
        let outer_hash_state = partial_sha256_digest(&opad);

        let (leader_msg, leader) = leader.next(inner_hash_state);
        let (follower_msg, follower) = follower.next(outer_hash_state).next(leader_msg);

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = follower_msg.a1;
        assert_eq!(
            &a1,
            &hmac_sha256(&ms, &seed_ke(&client_random, &server_random))
        );

        let (leader_msg, leader) = leader.next(follower_msg);
        let follower_msg = follower.next(leader_msg);

        // H((ms xor opad) || H((ms xor ipad) || a1))
        let a2 = follower_msg.a2;
        assert_eq!(&a2, &hmac_sha256(&ms, &a1));

        let leader = leader.next(follower_msg);

        let p1 = finalize_sha256_digest(outer_hash_state, 64, &leader.p1_inner_hash());
        let p2 = finalize_sha256_digest(outer_hash_state, 64, &leader.p2_inner_hash());

        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);

        // reference values were computed with python3:
        // import scapy
        // from scapy.layers.tls.crypto import prf
        // prffn = prf.PRF()
        // cr = bytes([0x01]*32)
        // sr = bytes([0x02]*32)
        // pms = bytes([0x03]*32)
        // ms = prffn.compute_master_secret(pms, cr, sr)
        // print(prffn.derive_key_block(ms, sr, cr, 40).hex())
        let reference_ek =
            "ede91cf0898c0ac272f1035fe20a8d24d90a6d3bf8be815b4a144cb270e3b8c8e00f2af71471ced8";
        assert_eq!(hex::encode(ek), reference_ek);
    }
}
