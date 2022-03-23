pub mod master;
mod sha;
pub mod slave;

pub use master::PrfMaster;
pub use slave::PrfSlave;

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha::{finalize_sha256_digest, partial_sha256_digest};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    #[test]
    fn test_prf() {
        let client_random = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let server_random = b"SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS";
        let pms = [0x99_u8; 32];

        let mut ipad = [0x36_u8; 64];
        let mut opad = [0x5c_u8; 64];

        for (ipad, pms) in ipad.iter_mut().zip(pms.iter()) {
            *ipad = *ipad ^ *pms;
        }
        for (opad, pms) in opad.iter_mut().zip(pms.iter()) {
            *opad = *opad ^ *pms;
        }

        let mut seed = [0u8; 77];
        seed[..13].copy_from_slice(b"master secret");
        seed[13..45].copy_from_slice(client_random);
        seed[45..].copy_from_slice(server_random);

        let mut expected_a1 = HmacSha256::new_from_slice(&pms).unwrap();
        expected_a1.update(&seed);
        let expected_a1 = expected_a1.finalize().into_bytes();
        let mut expected_a2 = HmacSha256::new_from_slice(&pms).unwrap();
        expected_a2.update(&expected_a1);
        let expected_a2 = expected_a2.finalize().into_bytes();

        let master = PrfMaster::new(*client_random, *server_random);
        let slave = PrfSlave::new();

        // H(pms xor ipad)
        let inner_hash_state = partial_sha256_digest(&ipad);
        // H(pms xor opad)
        let outer_hash_state = partial_sha256_digest(&opad);

        let (message, master) = master.next(inner_hash_state.clone());
        let (message, slave) = slave.next(outer_hash_state.clone(), message);

        // H((pms xor opad) || H((pms xor ipad) || seed))
        let a1 = message.a1.clone();

        assert_eq!(&a1, &expected_a1.as_slice());

        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);

        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = message.a2.clone();

        assert_eq!(&a2, &expected_a2.as_slice());

        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);

        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        let p2 = message.p2.clone();

        // a1 || seed
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);

        // H((pms xor opad) || H((pms xor ipad) || a1 || seed))
        let p1 = finalize_sha256_digest(outer_hash_state, 64, &a1_seed);

        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..48].copy_from_slice(&p2[..16]);

        let mut ipad = [0x36_u8; 64];
        let mut opad = [0x5c_u8; 64];

        for (ipad, ms) in ipad.iter_mut().zip(ms.iter()) {
            *ipad = *ipad ^ *ms;
        }
        for (opad, ms) in opad.iter_mut().zip(ms.iter()) {
            *opad = *opad ^ *ms;
        }

        // H(ms xor ipad)
        let inner_hash_state = partial_sha256_digest(&ipad);
        // H(ms xor opad)
        let outer_hash_state = partial_sha256_digest(&opad);

        let (message, master) = master.next(inner_hash_state.clone());
        let (message, slave) = slave.next(outer_hash_state.clone(), message);

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = message.a1.clone();

        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);

        // H((ms xor opad) || H((ms xor ipad) || a1))
        let a2 = message.a2.clone();

        let (inner_hashes, master) = master.next(message);

        let p1 = finalize_sha256_digest(outer_hash_state.clone(), 64, &inner_hashes.inner_hash_p1);
        let p2 = finalize_sha256_digest(outer_hash_state, 64, &inner_hashes.inner_hash_p2);

        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);
    }
}
