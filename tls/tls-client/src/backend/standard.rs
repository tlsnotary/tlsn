use super::{Backend, BackendError};
use crate::{DecryptMode, EncryptMode, Error};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    Aes128Gcm,
};
use async_trait::async_trait;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey as ECDHPublicKey};
use rand::{rngs::OsRng, thread_rng, Rng};

use digest::Digest;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::convert::TryInto;
use tls_core::{
    key::PublicKey,
    msgs::{
        base::Payload as TLSPayload,
        enums::{CipherSuite, ContentType, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::{self, SupportedCipherSuite},
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(input);
    let out = mac.finalize().into_bytes();
    out[..32]
        .try_into()
        .expect("expected output to be 32 bytes")
}

pub(crate) fn seed_ms(client_random: &[u8; 32], server_random: &[u8; 32]) -> [u8; 77] {
    let mut seed = [0u8; 77];
    seed[..13].copy_from_slice(b"master secret");
    seed[13..45].copy_from_slice(client_random);
    seed[45..].copy_from_slice(server_random);
    seed
}

pub(crate) fn seed_ke(client_random: &[u8; 32], server_random: &[u8; 32]) -> [u8; 77] {
    let mut seed = [0u8; 77];
    seed[..13].copy_from_slice(b"key expansion");
    seed[13..45].copy_from_slice(server_random);
    seed[45..].copy_from_slice(client_random);
    seed
}

pub(crate) fn seed_cf(handshake_blob: &[u8]) -> [u8; 47] {
    let mut hasher = Sha256::new();
    hasher.update(handshake_blob);
    let mut seed = [0u8; 47];
    seed[..15].copy_from_slice(b"client finished");
    seed[15..].copy_from_slice(hasher.finalize().as_slice());
    seed
}

pub(crate) fn seed_sf(handshake_blob: &[u8]) -> [u8; 47] {
    let mut hasher = Sha256::new();
    hasher.update(handshake_blob);
    let mut seed = [0u8; 47];
    seed[..15].copy_from_slice(b"server finished");
    seed[15..].copy_from_slice(hasher.finalize().as_slice());
    seed
}

/// Implementation of TLS backend using RustCrypto primitives
pub struct RustCryptoBackend {
    client_random: Option<Random>,
    server_random: Option<Random>,
    // master_secret size is the same for all cipher suites
    master_secret: Option<[u8; 48]>,
    // extended master secret seed
    ems_seed: Option<Vec<u8>>,
    ecdh_pubkey: Option<Vec<u8>>,
    ecdh_secret: Option<EphemeralSecret>,
    // session_keys size can vary depending on the ciphersuite
    session_keys: Option<Vec<u8>>,
    protocol_version: Option<ProtocolVersion>,
    cipher_suite: Option<SupportedCipherSuite>,
    curve: Option<NamedGroup>,
    implemented_suites: [CipherSuite; 2],
    encrypter: Option<Encrypter>,
    decrypter: Option<Decrypter>,
}

impl RustCryptoBackend {
    /// Creates new instance of RustCrypto backend
    pub fn new() -> Self {
        Self {
            client_random: None,
            server_random: None,
            ecdh_pubkey: None,
            ecdh_secret: None,
            master_secret: None,
            ems_seed: None,
            session_keys: None,
            protocol_version: None,
            cipher_suite: None,
            curve: Some(NamedGroup::secp256r1),
            implemented_suites: [
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            encrypter: None,
            decrypter: None,
        }
    }

    /// Expands the handshake hash and master secret into verify_data for
    /// the Server_Finished
    pub fn verify_data_sf_tls12(&mut self, hs_hash: &[u8], ms: &[u8; 48]) -> [u8; 12] {
        let mut seed = [0u8; 47];
        seed[..15].copy_from_slice(b"server finished");
        seed[15..].copy_from_slice(hs_hash);
        let a1 = hmac_sha256(ms, &seed);
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&hmac_sha256(ms, &a1_seed)[..12]);
        verify_data
    }

    /// Expands pre-master secret into session key using TLS 1.2 PRF
    /// Returns master_secret and session keys
    pub fn key_expansion_tls12(
        &mut self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        pms: &[u8],
    ) -> ([u8; 48], [u8; 40]) {
        // first expand pms into ms
        let seed = seed_ms(client_random, server_random);
        let a1 = hmac_sha256(pms, &seed);
        let a2 = hmac_sha256(pms, &a1);
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed);
        let p1 = hmac_sha256(pms, &a1_seed);
        let p2 = hmac_sha256(pms, &a2_seed);
        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..].copy_from_slice(&p2[..16]);
        let ms_out = ms.clone();

        // expand ms into session keys
        let seed = seed_ke(client_random, server_random);
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
        (ms_out, ek)
    }

    /// Expands the handshake hash and master secret into verify_data for
    /// the Client_Finished
    pub fn verify_data_cf_tls12(&mut self, hs_hash: &[u8], ms: &[u8; 48]) -> [u8; 12] {
        let mut seed = [0u8; 47];
        seed[..15].copy_from_slice(b"client finished");
        seed[15..].copy_from_slice(hs_hash);
        let a1 = hmac_sha256(ms, &seed);
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&hmac_sha256(ms, &a1_seed)[..12]);
        verify_data
    }

    fn set_encrypter(&mut self) -> Result<(), BackendError> {
        let cipher_suite = self.cipher_suite.ok_or(BackendError::InvalidState(
            "can not set enccrypter, ciphersuite not set".to_string(),
        ))?;

        match cipher_suite.suite() {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                // extract client_write_key and client_write_iv. They may be at different
                // offsets depending on the cipher suite.
                let mut write_key = [0u8; 16];
                let mut write_iv = [0u8; 4];
                let session_keys = self
                    .session_keys
                    .as_ref()
                    .ok_or(BackendError::InvalidState(
                        "can not set encrypter, session_keys are not set".to_string(),
                    ))?;
                write_key.copy_from_slice(&session_keys[0..16]);
                write_iv.copy_from_slice(&session_keys[32..36]);
                self.encrypter = Some(Encrypter::new(write_key, write_iv, cipher_suite.suite()));
            }
            suite => return Err(BackendError::UnsupportedCiphersuite(suite)),
        }
        Ok(())
    }
    fn set_decrypter(&mut self) -> Result<(), BackendError> {
        let cipher_suite = self.cipher_suite.ok_or(BackendError::InvalidState(
            "can not set decrypter, ciphersuite not set".to_string(),
        ))?;

        match cipher_suite.suite() {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                // extract server_write_key and server_write_iv. They may be at different
                // offsets depending on the cipher suite.
                let mut write_key = [0u8; 16];
                let mut write_iv = [0u8; 4];
                let session_keys = self
                    .session_keys
                    .as_ref()
                    .ok_or(BackendError::InvalidState(
                        "can not set decrypter, session_keys are not set".to_string(),
                    ))?;
                write_key.copy_from_slice(&session_keys[16..32]);
                write_iv.copy_from_slice(&session_keys[36..40]);
                self.decrypter = Some(Decrypter::new(write_key, write_iv, cipher_suite.suite()));
            }
            suite => return Err(BackendError::UnsupportedCiphersuite(suite)),
        }
        Ok(())
    }
}

#[async_trait]
impl Backend for RustCryptoBackend {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        match version {
            ProtocolVersion::TLSv1_2 => {
                self.protocol_version = Some(version);
                Ok(())
            }
            version => return Err(BackendError::UnsupportedProtocolVersion(version)),
        }
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        let version = self.protocol_version.ok_or(BackendError::InvalidState(
            "can not set ciphersuite, protocol version not set".to_string(),
        ))?;

        if suite.version().version != version {
            return Err(BackendError::InvalidConfig(
                "Ciphersuite protocol version does not match configured version".to_string(),
            ));
        }

        if !self.implemented_suites.contains(&suite.suite()) {
            return Err(BackendError::UnsupportedCiphersuite(suite.suite()));
        }
        self.cipher_suite = Some(suite);

        Ok(())
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        // TODO: do we assume already having probed the TLS server by this point
        // so that we know the exact ciphersuite it supports? Otherwise, we may
        // want to return multiple CSs here.
        // TODO can we just return the CipherSuite enum?
        Ok(suites::tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    }

    async fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), BackendError> {
        todo!()
    }

    async fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), BackendError> {
        todo!()
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        // generate client random and store it
        let r = Random(thread_rng().gen());
        self.client_random = Some(r);
        Ok(r)
    }

    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        // TODO make sure this and other methods are not called twice/out of order
        // generate our ECDH keypair
        let sk = EphemeralSecret::random(&mut OsRng);
        let pk_bytes = EncodedPoint::from(sk.public_key()).to_bytes().to_vec();
        self.ecdh_pubkey = Some(pk_bytes.clone());
        self.ecdh_secret = Some(sk);

        // return our ECDH pubkey
        let group = self.curve.ok_or(BackendError::InvalidState(
            "ECDH key curve not set yet".to_string(),
        ))?;

        Ok(PublicKey {
            group,
            key: pk_bytes,
        })
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        // store server random
        self.server_random = Some(random);
        Ok(())
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        // convert raw server ECDH pubkey to an object
        let server_pk =
            ECDHPublicKey::from_sec1_bytes(&key.key).map_err(|_| BackendError::InvalidServerKey)?;

        let sk = self.ecdh_secret.as_ref().unwrap();
        // perform ECDH, obtain PMS (which is the X coordinate of the resulting
        // EC point). The size of X for 256-bit curves is 32 bytes, for 384-bit
        // curves it is 48 bytes etc.
        let x_size = match self.curve.ok_or(BackendError::InvalidState(
            "ECDH key curve not set yet".to_string(),
        ))? {
            NamedGroup::secp256r1 => 32,
            NamedGroup::secp384r1 => 48,
            group => return Err(BackendError::UnsupportedCurveGroup(group)),
        };

        let mut pms = vec![0u8; x_size];
        let secret = *sk.diffie_hellman(&server_pk).as_bytes();
        pms.copy_from_slice(&secret);

        let (client_random, server_random) = match (self.client_random, self.server_random) {
            (Some(cr), Some(sr)) => (cr.0, sr.0),
            _ => {
                return Err(BackendError::InvalidState(
                    "Client_random and/or server_random not set".to_string(),
                ))
            }
        };

        (self.master_secret, self.session_keys) = match self.protocol_version.ok_or(
            BackendError::InvalidState("Protocol version not set".to_string()),
        )? {
            ProtocolVersion::TLSv1_2 => {
                let (ms, ek) = self.key_expansion_tls12(&client_random, &server_random, &pms);
                (Some(ms), Some(ek.to_vec()))
            }
            version => return Err(BackendError::UnsupportedProtocolVersion(version)),
        };

        self.set_encrypter()?;
        self.set_decrypter()?;

        Ok(())
    }

    async fn set_hs_hash_client_key_exchange(&mut self, hash: &[u8]) -> Result<(), BackendError> {
        self.ems_seed = Some(hash.to_vec());
        Ok(())
    }

    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    async fn get_server_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>, BackendError> {
        let ms = self.master_secret.ok_or(BackendError::InvalidState(
            "Master secret not set".to_string(),
        ))?;

        let verify_data = match self.protocol_version.ok_or(BackendError::InvalidState(
            "Protocol version not set".to_string(),
        ))? {
            ProtocolVersion::TLSv1_2 => self.verify_data_sf_tls12(hash, &ms),
            _ => unreachable!(),
        };
        Ok(verify_data.to_vec())
    }

    async fn get_client_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>, BackendError> {
        let ms = self.master_secret.ok_or(BackendError::InvalidState(
            "Master secret not set".to_string(),
        ))?;

        let verify_data = match self.protocol_version.ok_or(BackendError::InvalidState(
            "Protocol version not set".to_string(),
        ))? {
            ProtocolVersion::TLSv1_2 => self.verify_data_cf_tls12(hash, &ms),
            _ => unreachable!(),
        };
        Ok(verify_data.to_vec())
    }

    async fn encrypt(
        &mut self,
        msg: PlainMessage,
        seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        let enc = self
            .encrypter
            .as_mut()
            .ok_or(BackendError::EncryptionError(
                "Encrypter not ready".to_string(),
            ))?;

        match enc.cipher_suite {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                match msg.version {
                    ProtocolVersion::TLSv1_2 => {
                        let explicit_nonce;
                        match msg.typ {
                            ContentType::Handshake => {
                                // In TLS 1.2 the only handshake message that needs to be
                                // encrypted by the client is Client_Finished.

                                // By fixing the explicit_nonce of Client_Finished, we
                                // can save a round-trip in GC (no need to run circuit c4.casm
                                // separately but can integrate it into c3.casm).
                                explicit_nonce = [0, 0, 0, 0, 0, 0, 0, 1];
                            }
                            ContentType::ApplicationData => {
                                explicit_nonce = thread_rng().gen();
                            }
                            _ => {
                                return Err(BackendError::EncryptionError(
                                    "Unexpected ContentType".to_string(),
                                ));
                            }
                        };
                        return enc.encrypt_aes128gcm(&msg, seq, &explicit_nonce);
                    }
                    version => {
                        return Err(BackendError::UnsupportedProtocolVersion(version));
                    }
                }
            }
            suite => {
                return Err(BackendError::UnsupportedCiphersuite(suite));
            }
        }
    }

    async fn decrypt(
        &mut self,
        msg: OpaqueMessage,
        seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        let dec = self
            .decrypter
            .as_mut()
            .ok_or(BackendError::DecryptionError(
                "Decrypter not ready".to_string(),
            ))?;

        match dec.cipher_suite {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => match msg.version {
                ProtocolVersion::TLSv1_2 => {
                    return dec.decrypt_aes128gcm(&msg, seq);
                }
                version => {
                    return Err(BackendError::UnsupportedProtocolVersion(version));
                }
            },
            suite => {
                return Err(BackendError::UnsupportedCiphersuite(suite));
            }
        }
    }
}

pub struct Encrypter {
    write_key: [u8; 16],
    write_iv: [u8; 4],
    cipher_suite: CipherSuite,
}

impl Encrypter {
    pub fn new(write_key: [u8; 16], write_iv: [u8; 4], cipher_suite: CipherSuite) -> Self {
        Self {
            write_key,
            write_iv,
            cipher_suite,
        }
    }

    /// Encrypt with AES128GCM using TLS-specific AAD.
    fn encrypt_aes128gcm(
        &self,
        m: &PlainMessage,
        seq: u64,
        explicit_nonce: &[u8; 8],
    ) -> Result<OpaqueMessage, BackendError> {
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8] = m.typ.get_u8();
        aad[9..11].copy_from_slice(&m.version.get_u16().to_be_bytes());
        aad[11..13].copy_from_slice(&(m.payload.0.len() as u16).to_be_bytes());
        let payload = Payload {
            msg: &m.payload.0,
            aad: &aad,
        };

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.write_iv);
        nonce[4..].copy_from_slice(explicit_nonce);
        let nonce = GenericArray::from_slice(&nonce);
        let cipher = Aes128Gcm::new_from_slice(&self.write_key).unwrap();
        // ciphertext will have the MAC appended
        let ciphertext = cipher.encrypt(nonce, payload).unwrap();

        // prepend the explicit nonce
        let mut nonce_ct_mac = vec![0u8; 0];
        nonce_ct_mac.extend(explicit_nonce.iter());
        nonce_ct_mac.extend(ciphertext.iter());
        let om = OpaqueMessage {
            typ: m.typ,
            version: m.version,
            payload: TLSPayload::new(nonce_ct_mac),
        };

        Ok(om)
    }
}

pub struct Decrypter {
    write_key: [u8; 16],
    write_iv: [u8; 4],
    cipher_suite: CipherSuite,
}

impl Decrypter {
    pub fn new(write_key: [u8; 16], write_iv: [u8; 4], cipher_suite: CipherSuite) -> Self {
        Self {
            write_key,
            write_iv,
            cipher_suite,
        }
    }

    fn decrypt_aes128gcm(&self, m: &OpaqueMessage, seq: u64) -> Result<PlainMessage, BackendError> {
        // TODO tls-client shouldnt call decrypt with CCS
        if m.typ == ContentType::ChangeCipherSpec {
            return Ok(PlainMessage {
                typ: m.typ,
                version: m.version,
                payload: TLSPayload(m.payload.0.clone()),
            });
        }
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8] = m.typ.get_u8();
        aad[9..11].copy_from_slice(&m.version.get_u16().to_be_bytes());
        // 8-byte explicit nonce and 16-byte MAC are not counted towards
        // plaintext size.
        aad[11..13].copy_from_slice(&((m.payload.0.len() - 24) as u16).to_be_bytes());
        let aes_payload = Payload {
            msg: &m.payload.0[8..],
            aad: &aad,
        };

        let cipher = Aes128Gcm::new_from_slice(&self.write_key).unwrap();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.write_iv);
        nonce[4..].copy_from_slice(&m.payload.0[0..8]);
        let nonce = GenericArray::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, aes_payload).unwrap();

        Ok(PlainMessage {
            typ: m.typ,
            version: m.version,
            payload: TLSPayload(plaintext),
        })
    }
}
