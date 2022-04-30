pub mod errors;
pub mod master;
mod sha;
pub mod slave;
mod utils;

pub use master::PRFMaster;
pub use slave::PRFSlave;

use master::{MasterKe1, MasterKe2, MasterKe3, MasterMs1, MasterMs2, MasterMs3};
use slave::{SlaveKe1, SlaveKe2, SlaveMs1, SlaveMs2, SlaveMs3};

#[derive(Copy, Clone)]
pub enum PRFMessage {
    MasterMs1(MasterMs1),
    SlaveMs1(SlaveMs1),
    MasterMs2(MasterMs2),
    SlaveMs2(SlaveMs2),
    MasterMs3(MasterMs3),
    SlaveMs3(SlaveMs3),
    MasterKe1(MasterKe1),
    SlaveKe1(SlaveKe1),
    MasterKe2(MasterKe2),
    SlaveKe2(SlaveKe2),
    MasterKe3(MasterKe3),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use sha::{finalize_sha256_digest, partial_sha256_digest};
    use utils::*;

    #[test]
    fn test_prf() {
        let client_random = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let server_random = b"SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS";
        let pms = [0x99_u8; 32];

        let (ipad, opad) = generate_hmac_pads(&pms);

        let mut master = PRFMaster::new(*client_random, *server_random);
        let mut slave = PRFSlave::new();

        // H(pms xor ipad)
        let inner_hash_state = partial_sha256_digest(&ipad);
        // H(pms xor opad)
        let outer_hash_state = partial_sha256_digest(&opad);

        let message = master.ms_setup(inner_hash_state).unwrap();
        let message = slave.next(message, Some(outer_hash_state)).unwrap();

        // H((pms xor opad) || H((pms xor ipad) || seed))
        let a1 = if let PRFMessage::SlaveMs1(m) = message {
            m.a1
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(
            &a1,
            &hmac_sha256(&pms, &seed_ms(client_random, server_random))
        );

        let message = master.next(message).unwrap();
        let message = slave.next(message, None).unwrap();

        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = if let PRFMessage::SlaveMs2(m) = message {
            m.a2
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(&a2, &hmac_sha256(&pms, &a1));

        let message = master.next(message).unwrap();
        let message = slave.next(message, None).unwrap();

        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        let p2 = if let PRFMessage::SlaveMs3(m) = message {
            m.p2
        } else {
            panic!("unable to destructure");
        };

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

        let message = master.ke_setup(inner_hash_state).unwrap();
        let message = slave.next(message, Some(outer_hash_state)).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = if let PRFMessage::SlaveKe1(m) = message {
            m.a1
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(
            &a1,
            &hmac_sha256(&ms, &seed_ke(&client_random, &server_random))
        );

        let message = master.next(message).unwrap();
        let message = slave.next(message, None).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || a1))
        let a2 = if let PRFMessage::SlaveKe2(m) = message {
            m.a2
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(&a2, &hmac_sha256(&ms, &a1));

        let message = master.next(message).unwrap();
        let (inner_hash_p1, inner_hash_p2) = if let PRFMessage::MasterKe3(m) = message {
            (m.inner_hash_p1, m.inner_hash_p1)
        } else {
            panic!("unable to destructure");
        };

        let p1 = finalize_sha256_digest(outer_hash_state.clone(), 64, &inner_hash_p1);
        let p2 = finalize_sha256_digest(outer_hash_state, 64, &inner_hash_p2);

        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);
        let mut cwk = [0u8; 16];
        cwk.copy_from_slice(&ek[..16]);

        let client_write_key = &ek[..16];
        let server_write_key = &ek[16..32];
        let client_write_iv = &ek[32..36];
        let server_write_iv = &ek[36..];

        // Seems like the simplest way to compare byte slices is to hex encode
        // them first.
        assert_eq!(
            hex::encode(&client_write_key),
            "24542375e0909cabc9976eaa009d283a"
        );
        assert_eq!(
            hex::encode(&server_write_key),
            "ca6e052ed8a4a07acecc55fc0ee335cc"
        );
        assert_eq!(hex::encode(&client_write_iv), "24542375");
        assert_eq!(hex::encode(&server_write_iv), "e0909cab");
    }
}
