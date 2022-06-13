use crate::Error;
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::Aes128Gcm;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey as ECDHPublicKey};
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use tls_aio::{
    cipher::{MessageDecrypter, MessageEncrypter},
    handshaker::Handshake,
};
use tls_core::handshake::utils::{hmac_sha256, seed_ke, seed_ms};
use tls_core::key::PublicKey;
use tls_core::msgs::base::Payload as TLSPayload;
use tls_core::msgs::enums::NamedGroup;
use tls_core::msgs::handshake::Random;
use tls_core::msgs::message::{OpaqueMessage, PlainMessage};

use async_trait::async_trait;

pub struct InvalidHandShaker {
    client_random: Option<Random>,
    server_random: Option<Random>,
    master_secret: Option<[u8; 48]>,
    ecdh_pubkey: Option<Vec<u8>>,
    expanded_keys: Option<[u8; 40]>,
}

impl InvalidHandShaker {
    pub fn new() -> Self {
        Self {
            client_random: None,
            server_random: None,
            ecdh_pubkey: None,
            master_secret: None,
            expanded_keys: None,
        }
    }
}

#[async_trait]
impl Handshake for InvalidHandShaker {
    type Error = Error;

    async fn client_random(&mut self) -> Result<Random, Error> {
        // generate client random and store it
        let rng = thread_rng();
        let r: [u8; 32] = rng.gen();
        let r = Random(r);
        self.client_random = Some(r);
        Ok(r)
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), Self::Error> {
        // store server random
        self.server_random = Some(random);
        Ok(())
    }

    async fn set_server_key_share(&mut self, server_pk: PublicKey) -> Result<(), Self::Error> {
        // TODO: is PublicKey the same as it appears on the wire (with the leading 0x04)?
        // get server ecdh pubkey
        let server_pk = ECDHPublicKey::from_sec1_bytes(&server_pk.key).unwrap();

        // generate our ecdh keypair
        let sk = EphemeralSecret::random(&mut OsRng);
        let pk_bytes = EncodedPoint::from(sk.public_key());
        // store our ecdh pubkey
        self.ecdh_pubkey = Some(pk_bytes.to_bytes().to_vec());

        // perform ecdh, obtain pms
        let pms_obj = sk.diffie_hellman(&server_pk);
        let pms = [0x03_u8; 32];
        pms.copy_from_slice(&pms_obj.as_bytes().as_slice()[0..32]);

        // expand pms (using cr, sr), get session keys
        let client_random = self.client_random.unwrap().0;
        let server_random = self.server_random.unwrap().0;

        // PRF as in test_prf() in tls-core/src/handshake/mod.rs
        let seed = seed_ms(&client_random, &server_random);
        let a1 = hmac_sha256(&pms, &seed);
        let a2 = hmac_sha256(&pms, &a1);
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed);
        let p1 = hmac_sha256(&pms, &a1_seed);
        let p2 = hmac_sha256(&pms, &a2_seed);
        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..].copy_from_slice(&p2[..16]);
        // store ms (for CF, SF later)
        self.master_secret = Some(ms);

        let seed = seed_ke(&client_random, &server_random);
        let a1 = hmac_sha256(&ms, &seed);
        let a2 = hmac_sha256(&ms, &a1);
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed);
        let p1 = hmac_sha256(&ms, &a1_seed);
        let p2 = hmac_sha256(&ms, &a2_seed);
        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);
        // store session keys
        self.expanded_keys = Some(ek);

        Ok(())
    }

    async fn client_key_share(&mut self) -> Result<PublicKey, Error> {
        // return our ecdh pubkey
        Ok(PublicKey {
            group: NamedGroup::secp256r1,
            key: self.ecdh_pubkey.unwrap(),
        })
    }

    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), Self::Error> {
        Ok(())
        // will be used only in 2PC

        // TODO the handshake hash is not up to Server Hello but must
        // be up to Client Key Exchange, so this fn should be called
        // receive_hs_hash_client_key_exchange
    }

    async fn client_finished(&mut self, hs_hash: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // TODO we must also return plaintext CF so that tls-client could update
        // the handshake hash

        // compute CF from ms + hash
        // PRF as in test_prf() in tls-core/src/handshake/mod.rs
        let ms = self.master_secret.unwrap();
        let mut seed = [0u8; 47];
        seed[..15].copy_from_slice(b"client finished");
        seed[15..].copy_from_slice(hs_hash);
        let a1 = hmac_sha256(&ms, &seed);
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&hmac_sha256(&ms, &a1_seed)[..12]);
        let mut client_finished = [0u8; 16];
        client_finished[..4].copy_from_slice(&[0x14, 0x00, 0x00, 0x0C]);
        client_finished[4..].copy_from_slice(&verify_data);

        // encrypt client finished
        let mut client_write_key = [0u8; 16];
        client_write_key.copy_from_slice(&self.expanded_keys.unwrap()[0..16]);
        let mut client_write_iv = [0u8; 4];
        client_write_iv.copy_from_slice(&self.expanded_keys.unwrap()[32..36]);

        let rng = thread_rng();
        let explicit_nonce: [u8; 8] = rng.gen();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&client_write_iv);
        nonce[4..].copy_from_slice(&explicit_nonce);
        let nonce = GenericArray::from_slice(&nonce);

        let cipher = Aes128Gcm::new_from_slice(&client_write_key).unwrap();
        let aad = [0u8; 13];
        // seq no 0
        aad[..8].copy_from_slice(&[0u8; 8]);
        // type 0x16 = Handshake; TLS Version 1.2; 16 bytes of unencrypted data
        aad[8..].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x10]);
        let payload = Payload {
            msg: &client_finished,
            aad: &aad,
        };
        // ciphertext will have the MAC appended
        let ciphertext = cipher.encrypt(nonce, payload).unwrap();
        // return plaintext CF, nonce+ciphertext
        // TODO prepend nonce to ciphertext
        Ok((ciphertext))
    }

    // TODO tls-client should pass in the explicit nonce from the server finished
    async fn server_finished(&mut self, hs_hash: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // compute SF from ms + hash
        // PRF as in test_prf() in tls-core/src/handshake/mod.rs
        let ms = self.master_secret.unwrap();
        let mut seed = [0u8; 47];
        seed[..15].copy_from_slice(b"server finished");
        seed[15..].copy_from_slice(hs_hash);
        let a1 = hmac_sha256(&ms, &seed);
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&hmac_sha256(&ms, &a1_seed)[..12]);
        let mut server_finished = [0u8; 16];
        server_finished[..4].copy_from_slice(&[0x14, 0x00, 0x00, 0x0C]);
        server_finished[4..].copy_from_slice(&verify_data);

        // encrypt server finished with explicit_nonce
        let mut server_write_key = [0u8; 16];
        server_write_key.copy_from_slice(&self.expanded_keys.unwrap()[16..32]);
        let mut server_write_iv = [0u8; 4];
        server_write_iv.copy_from_slice(&self.expanded_keys.unwrap()[36..40]);

        let rng = thread_rng();
        // TODO this should be passed to us by tls-client
        let explicit_nonce: [u8; 8] = rng.gen();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&server_write_iv);
        nonce[4..].copy_from_slice(&explicit_nonce);
        let nonce = GenericArray::from_slice(&nonce);

        let cipher = Aes128Gcm::new_from_slice(&server_write_key).unwrap();
        let aad = [0u8; 13];
        // seq no 0
        aad[..8].copy_from_slice(&[0u8; 8]);
        // type 0x16 = Handshake; TLS Version 1.2; 16 bytes of unencrypted data
        aad[8..].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x10]);
        let payload = Payload {
            msg: &server_finished,
            aad: &aad,
        };
        // ciphertext will have the MAC appended
        let ciphertext = cipher.encrypt(nonce, payload).unwrap();
        // return ciphertext
        Ok((ciphertext))
    }

    async fn message_encrypter(
        &mut self,
    ) -> Result<Box<dyn MessageEncrypter<Error = Self::Error>>, Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn message_decrypter(
        &mut self,
    ) -> Result<Box<dyn MessageDecrypter<Error = Self::Error>>, Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
}

pub struct Encrypter {
    write_key: [u8; 16],
    write_iv: [u8; 4],
}

impl Encrypter {
    pub fn new(write_key: [u8; 16], write_iv: [u8; 4]) -> Self {
        Self {
            write_key,
            write_iv,
        }
    }
}

#[async_trait]
impl MessageEncrypter for Encrypter {
    type Error = Error;

    async fn encrypt(&self, m: PlainMessage, seq: u64) -> Result<OpaqueMessage, Self::Error> {
        // TODO for now assuming that payload size < 16 KB and can fit into 1 TLS record
        let cipher = Aes128Gcm::new_from_slice(&self.write_key).unwrap();
        let aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        // Type 0x17: Application data; TLS Version 1.2;
        aad[8..11].copy_from_slice(&[0x17, 0x03, 0x03]);
        // plaintext size in bytes
        aad[11..].copy_from_slice(&(m.payload.0.len() as u16).to_be_bytes());
        let aes_payload = Payload {
            msg: &m.payload.0,
            aad: &aad,
        };
        let rng = thread_rng();
        let explicit_nonce: [u8; 8] = rng.gen();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.write_iv);
        nonce[4..].copy_from_slice(&explicit_nonce);
        let nonce = GenericArray::from_slice(&nonce);
        // ciphertext will have the MAC appended
        let ciphertext = cipher.encrypt(nonce, aes_payload).unwrap();
        let encr_payload = vec![0u8; 0];
        encr_payload.extend(explicit_nonce.iter());
        encr_payload.extend(ciphertext.iter());

        Ok(OpaqueMessage {
            typ: m.typ,
            version: m.version,
            payload: TLSPayload(encr_payload),
        })
    }
}

pub struct Decrypter {
    write_key: [u8; 16],
    write_iv: [u8; 4],
}

impl Decrypter {
    pub fn new(write_key: [u8; 16], write_iv: [u8; 4]) -> Self {
        Self {
            write_key,
            write_iv,
        }
    }
}

#[async_trait]
impl MessageDecrypter for Decrypter {
    type Error = Error;

    async fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Self::Error> {
        // TODO for now assuming that payload size < 16 KB and can fit into 1 TLS record

        let cipher = Aes128Gcm::new_from_slice(&self.write_key).unwrap();
        let aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        // Type 0x17: Application data; TLS Version 1.2;
        aad[8..11].copy_from_slice(&[0x17, 0x03, 0x03]);
        // plaintext size in bytes
        aad[11..].copy_from_slice(&(m.payload.0.len() as u16).to_be_bytes());
        let explicit_nonce = [0u8; 0];
        explicit_nonce.copy_from_slice(&m.payload.0[0..8]);
        let ciphertext = &m.payload.0[8..];
        let aes_payload = Payload {
            msg: &ciphertext,
            aad: &aad,
        };

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.write_iv);
        nonce[4..].copy_from_slice(&explicit_nonce);
        let nonce = GenericArray::from_slice(&nonce);
        // ciphertext will have the MAC appended
        let plaintext = cipher.decrypt(nonce, aes_payload).unwrap();

        Ok(PlainMessage {
            typ: m.typ,
            version: m.version,
            payload: TLSPayload(plaintext),
        })
    }
}
