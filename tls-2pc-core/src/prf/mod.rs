//! This module contains the protocol for computing TLS SHA-256 HMAC PRF using 2PC in such a way
//! that neither party learns the session keys, rather they learn respective XOR shares of the keys.
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

mod follower;
mod leader;
pub mod sha;
mod utils;

pub use crate::msgs::prf::PRFMessage;
pub use follower::{state as follower_state, PRFFollower};
pub use leader::{state as leader_state, PRFLeader};

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use sha::{finalize_sha256_digest, partial_sha256_digest};
    use utils::*;

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

        let leader = PRFLeader::new(client_random, server_random, inner_hash_state);
        let follower = PRFFollower::new(outer_hash_state);

        let (leader_msg, leader) = leader.next();
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((pms xor opad) || H((pms xor ipad) || seed))
        let a1 = follower_msg.a1.clone();
        assert_eq!(
            &a1,
            &hmac_sha256(&pms, &seed_ms(&client_random, &server_random))
        );

        let (leader_msg, leader) = leader.next(follower_msg);
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = follower_msg.a2.clone();
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
        let a1 = follower_msg.a1.clone();
        assert_eq!(
            &a1,
            &hmac_sha256(&ms, &seed_ke(&client_random, &server_random))
        );

        let (leader_msg, leader) = leader.next(follower_msg);
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((ms xor opad) || H((ms xor ipad) || a1))
        let a2 = follower_msg.a2.clone();
        assert_eq!(&a2, &hmac_sha256(&ms, &a1));

        let leader = leader.next(follower_msg);

        let p1 = finalize_sha256_digest(outer_hash_state, 64, &leader.p1_inner_hash());
        let p2 = finalize_sha256_digest(outer_hash_state, 64, &leader.p2_inner_hash());

        let leader = leader.next();

        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);

        let handshake_blob = [0x04_u8; 256];
        let (leader_msg, leader) = leader.next(&handshake_blob);
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = follower_msg.a1.clone();
        assert_eq!(&a1, &hmac_sha256(&ms, &seed_cf(&handshake_blob)));

        let (leader_msg, leader) = leader.next(follower_msg);
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
        let vd = follower_msg.verify_data.clone();
        // a1 || seed
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed_cf(&handshake_blob));
        assert_eq!(&vd, &hmac_sha256(&ms, &a1_seed)[..12]);

        let (cfvd, leader) = leader.next(follower_msg);

        let (leader_msg, leader) = leader.next(&handshake_blob);
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = follower_msg.a1.clone();
        assert_eq!(&a1, &hmac_sha256(&ms, &seed_sf(&handshake_blob)));

        let (leader_msg, leader) = leader.next(follower_msg);
        let follower_msg = follower.next(leader_msg);

        // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
        let vd = follower_msg.verify_data;
        // a1 || seed
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed_sf(&handshake_blob));
        assert_eq!(&vd, &hmac_sha256(&ms, &a1_seed)[..12]);

        let sfvd = leader.next(follower_msg);

        // reference values were computed with python3:
        // import scapy
        // from scapy.layers.tls.crypto import prf
        // prffn = prf.PRF()
        // cr = bytes([0x01]*32)
        // sr = bytes([0x02]*32)
        // pms = bytes([0x03]*32)
        // handshake_blob = bytes([0x04]*256)
        // ms = prffn.compute_master_secret(pms, cr, sr)
        // print(prffn.derive_key_block(ms, sr, cr, 40).hex())
        // print(prffn.compute_verify_data("client", "write", handshake_blob, ms).hex())
        // print(prffn.compute_verify_data("server", "write", handshake_blob, ms).hex())
        let reference_ek =
            "ede91cf0898c0ac272f1035fe20a8d24d90a6d3bf8be815b4a144cb270e3b8c8e00f2af71471ced8";
        let reference_cfvd = "dc9906a43d25742bc6a479c2";
        let reference_sfvd = "d9f56d1223dea4832a7d8295";
        assert_eq!(hex::encode(&ek), reference_ek);
        assert_eq!(hex::encode(&cfvd), reference_cfvd);
        assert_eq!(hex::encode(&sfvd), reference_sfvd);
    }
}
