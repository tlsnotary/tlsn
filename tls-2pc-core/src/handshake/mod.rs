pub mod errors;
pub mod master;
mod sha;
pub mod slave;
mod utils;

pub use crate::msgs::handshake::HandshakeMessage;
use errors::*;
pub use master::HandshakeMasterCore;
pub use slave::HandshakeSlaveCore;

pub trait MasterCore {
    /// The first method that should be called after instantiation. Performs
    /// setup before we can process master secret related messages.
    fn ms_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<HandshakeMessage, HandshakeError>;

    // Performs setup before we can process key expansion related messages.
    fn ke_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<HandshakeMessage, HandshakeError>;

    // Performs setup before we can process Client_Finished related messages.
    fn cf_setup(&mut self, handshake_blob: &[u8]) -> Result<HandshakeMessage, HandshakeError>;

    // Performs setup before we can process Server_Finished related messages.
    fn sf_setup(&mut self, handshake_blob: &[u8]) -> Result<HandshakeMessage, HandshakeError>;

    /// Will be called repeatedly whenever there is a message from Slave that
    /// needs to be processed.
    fn next(
        &mut self,
        message: HandshakeMessage,
    ) -> Result<Option<HandshakeMessage>, HandshakeError>;

    // Returns inner_hashes for p1 and p2 for key expansion
    fn get_inner_hashes_ke(self) -> Result<([u8; 32], [u8; 32]), HandshakeError>;

    // Returns verify_data for Client_Finished
    fn get_client_finished_vd(self) -> Result<[u8; 12], HandshakeError>;

    // Returns verify_data for Server_Finished
    fn get_server_finished_vd(self) -> Result<[u8; 12], HandshakeError>;
}

pub trait SlaveCore {
    /// The first method that should be called after instantiation. Performs
    /// setup before we can process master secret related messages.
    fn ms_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), HandshakeError>;

    // Performs setup before we can process key expansion related messages.
    fn ke_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), HandshakeError>;

    /// Will be called repeatedly whenever there is a message from Master that
    /// needs to be processed.
    fn next(&mut self, message: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError>;
}

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

        let mut master = HandshakeMasterCore::new(client_random, server_random);
        let mut slave = HandshakeSlaveCore::new();

        // H(pms xor ipad)
        let inner_hash_state = partial_sha256_digest(&ipad);
        // H(pms xor opad)
        let outer_hash_state = partial_sha256_digest(&opad);

        let message = master.ms_setup(inner_hash_state).unwrap();
        slave.ms_setup(outer_hash_state).unwrap();
        let message = slave.next(message).unwrap();

        // H((pms xor opad) || H((pms xor ipad) || seed))
        let a1 = if let HandshakeMessage::SlaveMs1(m) = message {
            m.a1
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(
            &a1,
            &hmac_sha256(&pms, &seed_ms(&client_random, &server_random))
        );

        let message = master.next(message).unwrap().unwrap();
        let message = slave.next(message).unwrap();

        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = if let HandshakeMessage::SlaveMs2(m) = message {
            m.a2
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(&a2, &hmac_sha256(&pms, &a1));

        let message = master.next(message).unwrap().unwrap();
        let message = slave.next(message).unwrap();

        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        let p2 = if let HandshakeMessage::SlaveMs3(m) = message {
            m.p2
        } else {
            panic!("unable to destructure");
        };
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

        let message = master.ke_setup(inner_hash_state).unwrap();
        slave.ke_setup(outer_hash_state).unwrap();
        let message = slave.next(message).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = if let HandshakeMessage::SlaveKe1(m) = message {
            m.a1
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(
            &a1,
            &hmac_sha256(&ms, &seed_ke(&client_random, &server_random))
        );

        let message = master.next(message).unwrap().unwrap();
        let message = slave.next(message).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || a1))
        let a2 = if let HandshakeMessage::SlaveKe2(m) = message {
            m.a2
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(&a2, &hmac_sha256(&ms, &a1));

        master.next(message).unwrap();
        let (inner_hash_p1, inner_hash_p2) = master.get_inner_hashes_ke().unwrap();

        let p1 = finalize_sha256_digest(outer_hash_state, 64, &inner_hash_p1);
        let p2 = finalize_sha256_digest(outer_hash_state, 64, &inner_hash_p2);

        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);

        let handshake_blob = [0x04_u8; 256];
        let message = master.cf_setup(&handshake_blob).unwrap();
        let message = slave.next(message).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = if let HandshakeMessage::SlaveCf1(m) = message {
            m.a1
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(&a1, &hmac_sha256(&ms, &seed_cf(&handshake_blob)));

        let message = master.next(message).unwrap().unwrap();
        let message = slave.next(message).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
        let vd = if let HandshakeMessage::SlaveCf2(m) = message {
            m.verify_data
        } else {
            panic!("unable to destructure");
        };
        // a1 || seed
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed_cf(&handshake_blob));
        assert_eq!(&vd, &hmac_sha256(&ms, &a1_seed)[..12]);

        master.next(message).unwrap();
        let cfvd = master.get_client_finished_vd().unwrap();

        let message = master.sf_setup(&handshake_blob).unwrap();
        let message = slave.next(message).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || seed))
        let a1 = if let HandshakeMessage::SlaveSf1(m) = message {
            m.a1
        } else {
            panic!("unable to destructure");
        };
        assert_eq!(&a1, &hmac_sha256(&ms, &seed_sf(&handshake_blob)));

        let message = master.next(message).unwrap().unwrap();
        let message = slave.next(message).unwrap();

        // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
        let vd = if let HandshakeMessage::SlaveSf2(m) = message {
            m.verify_data
        } else {
            panic!("unable to destructure");
        };
        // a1 || seed
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed_sf(&handshake_blob));
        assert_eq!(&vd, &hmac_sha256(&ms, &a1_seed)[..12]);

        master.next(message).unwrap();
        let sfvd = master.get_server_finished_vd().unwrap();

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
