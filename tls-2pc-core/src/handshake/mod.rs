mod follower;
mod leader;
pub mod sha;
mod utils;

pub use crate::msgs::handshake::HandshakeMessage;
pub use follower::HandshakeFollower;
pub use leader::HandshakeLeader;

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

        let leader = HandshakeLeader::new(client_random, server_random, inner_hash_state);
        let follower = HandshakeFollower::new(outer_hash_state);

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
        let (follower_msg, follower) = follower.next(leader_msg);

        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        let p2 = follower_msg.p2.clone();
        // a2 || seed
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed_ms(&client_random, &server_random));
        assert_eq!(&p2, &hmac_sha256(&pms, &a2_seed));

        // a1 || seed
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed_ms(&client_random, &server_random));

        // H((pms xor opad) || H((pms xor ipad) || a1 || seed))
        let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &a1_seed);
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

        let ((inner_hash_p1, inner_hash_p2), leader) = leader.next(follower_msg);

        let p1 = finalize_sha256_digest(outer_hash_state, 64, &inner_hash_p1);
        let p2 = finalize_sha256_digest(outer_hash_state, 64, &inner_hash_p2);

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
