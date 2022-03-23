pub mod master;
mod sha;
pub mod slave;
mod utils;

pub use master::PrfMaster;
pub use slave::PrfSlave;

#[cfg(test)]
mod tests {
    use super::*;
    use sha::{finalize_sha256_digest, partial_sha256_digest};
    use utils::*;

    #[test]
    fn test_prf() {
        let client_random = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let server_random = b"SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS";
        let pms = [0x99_u8; 32];

        let (ipad, opad) = generate_hmac_pads(&pms);

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
        assert_eq!(
            &a1,
            &hmac_sha256(&pms, &seed_ms(client_random, server_random))
        );

        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);

        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = message.a2.clone();
        assert_eq!(&a2, &hmac_sha256(&pms, &a1));

        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);

        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        let p2 = message.p2.clone();

        // a1 || seed
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed_ms(client_random, server_random));

        // H((pms xor opad) || H((pms xor ipad) || a1 || seed))
        let p1 = finalize_sha256_digest(outer_hash_state, 64, &a1_seed);

        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..48].copy_from_slice(&p2[..16]);

        let (ipad, opad) = generate_hmac_pads(&ms);

        // H(ms xor ipad)
        let inner_hash_state = partial_sha256_digest(&ipad);
        // H(ms xor opad)
        let outer_hash_state = partial_sha256_digest(&opad);

        let (message, master) = master.next(inner_hash_state.clone());
        let (message, slave) = slave.next(outer_hash_state.clone(), message);

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = message.a1.clone();
        assert_eq!(
            &a1,
            &hmac_sha256(&ms, &seed_ke(&client_random, &server_random))
        );

        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);

        // H((ms xor opad) || H((ms xor ipad) || a1))
        let a2 = message.a2.clone();
        assert_eq!(&a2, &hmac_sha256(&ms, &a1));

        let (inner_hashes, master) = master.next(message);

        let p1 = finalize_sha256_digest(outer_hash_state.clone(), 64, &inner_hashes.inner_hash_p1);
        let p2 = finalize_sha256_digest(outer_hash_state, 64, &inner_hashes.inner_hash_p2);

        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);
        let client_write_key = &ek[..16];
        let server_write_key = &ek[16..32];
        let client_write_iv = &ek[32..36];
        let server_write_iv = &ek[36..];
    }
}
