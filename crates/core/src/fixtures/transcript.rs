//! Transcript fixtures for testing.

use aead::Payload as AeadPayload;
use aes_gcm::{aead::Aead, Aes128Gcm, NewAead};
use generic_array::GenericArray;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tls_core::msgs::{
    base::Payload,
    codec::Codec,
    enums::{HandshakeType, ProtocolVersion},
    handshake::{HandshakeMessagePayload, HandshakePayload},
    message::{OpaqueMessage, PlainMessage},
};

use crate::{
    connection::{TranscriptLength, VerifyData},
    fixtures::ConnectionFixture,
    transcript::{Record, TlsTranscript, ContentType},
};

/// The key used for encryption of the sent and received transcript.
pub const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// The iv used for encryption of the sent and received transcript.
pub const IV: [u8; 4] = [1, 3, 3, 7];

/// The record size in bytes.
pub const RECORD_SIZE: usize = 512;

/// Creates a transript fixture for testing.
pub fn transcript_fixture(sent: &[u8], recv: &[u8]) -> TlsTranscript {
    TranscriptGenerator::new(KEY, IV).generate(sent, recv)
}

struct TranscriptGenerator {
    key: [u8; 16],
    iv: [u8; 4],
}

impl TranscriptGenerator {
    fn new(key: [u8; 16], iv: [u8; 4]) -> Self {
        Self { key, iv }
    }

    fn generate(&self, sent: &[u8], recv: &[u8]) -> TlsTranscript {
        let mut rng = StdRng::from_seed([1; 32]);

        let transcript_len = TranscriptLength {
            sent: sent.len() as u32,
            received: recv.len() as u32,
        };
        let tlsn = ConnectionFixture::tlsnotary(transcript_len);

        let time = tlsn.connection_info.time;
        let version = tlsn.connection_info.version;
        let server_cert_chain = tlsn.server_cert_data.certs;
        let server_signature = tlsn.server_cert_data.sig;
        let cert_binding = tlsn.server_cert_data.binding;

        let cf_vd: [u8; 12] = rng.random();
        let sf_vd: [u8; 12] = rng.random();

        let verify_data = VerifyData {
            client_finished: cf_vd.to_vec(),
            server_finished: sf_vd.to_vec(),
        };

        let sent = self.gen_records(cf_vd, sent);
        let recv = self.gen_records(sf_vd, recv);

        TlsTranscript::new(
            time,
            version,
            Some(server_cert_chain),
            Some(server_signature),
            cert_binding,
            verify_data,
            sent,
            recv,
        )
        .unwrap()
    }

    fn gen_records(&self, vd: [u8; 12], plaintext: &[u8]) -> Vec<Record> {
        let mut records = Vec::new();

        let handshake = self.gen_handshake(vd);
        records.push(handshake);

        for (seq, msg) in (1_u64..).zip(plaintext.chunks(RECORD_SIZE)) {
            let record = self.gen_app_data(seq, msg);
            records.push(record);
        }

        records
    }

    fn gen_app_data(&self, seq: u64, plaintext: &[u8]) -> Record {
        assert!(
            plaintext.len() <= 1 << 14,
            "plaintext len per record must be smaller than 2^14 bytes"
        );

        let explicit_nonce: [u8; 8] = seq.to_be_bytes();
        let msg = PlainMessage {
            typ: ContentType::ApplicationData.into(),
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(plaintext),
        };
        let opaque = aes_gcm_encrypt(self.key, self.iv, seq, explicit_nonce, &msg);

        let mut payload = opaque.payload.0;
        let mut ciphertext = payload.split_off(8);
        let tag = ciphertext.split_off(ciphertext.len() - 16);

        Record {
            seq,
            typ: ContentType::ApplicationData,
            plaintext: Some(plaintext.to_vec()),
            explicit_nonce: explicit_nonce.to_vec(),
            ciphertext,
            tag: Some(tag),
        }
    }

    fn gen_handshake(&self, vd: [u8; 12]) -> Record {
        let seq = 0_u64;
        let explicit_nonce = seq.to_be_bytes();

        let mut plaintext = Vec::new();

        let payload = Payload(vd.to_vec());
        let hs_payload = HandshakePayload::Finished(payload);
        let handshake_message = HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: hs_payload,
        };
        handshake_message.encode(&mut plaintext);

        let msg = PlainMessage {
            typ: ContentType::Handshake.into(),
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(plaintext.clone()),
        };

        let opaque = aes_gcm_encrypt(self.key, self.iv, seq, explicit_nonce, &msg);
        let mut payload = opaque.payload.0;
        let mut ciphertext = payload.split_off(8);
        let tag = ciphertext.split_off(ciphertext.len() - 16);

        Record {
            seq,
            typ: ContentType::Handshake,
            plaintext: Some(plaintext),
            explicit_nonce: explicit_nonce.to_vec(),
            ciphertext,
            tag: Some(tag),
        }
    }
}

fn aes_gcm_encrypt(
    key: [u8; 16],
    iv: [u8; 4],
    seq: u64,
    explicit_nonce: [u8; 8],
    msg: &PlainMessage,
) -> OpaqueMessage {
    let mut aad = [0u8; 13];

    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = msg.typ.get_u8();
    aad[9..11].copy_from_slice(&msg.version.get_u16().to_be_bytes());
    aad[11..13].copy_from_slice(&(msg.payload.0.len() as u16).to_be_bytes());
    let payload = AeadPayload {
        msg: &msg.payload.0,
        aad: &aad,
    };

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&iv);
    nonce[4..].copy_from_slice(&explicit_nonce);
    let nonce = GenericArray::from_slice(&nonce);
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();

    // ciphertext will have the MAC appended
    let ciphertext = cipher.encrypt(nonce, payload).unwrap();

    // prepend the explicit nonce
    let mut nonce_ct_mac = vec![0u8; 0];
    nonce_ct_mac.extend(explicit_nonce.iter());
    nonce_ct_mac.extend(ciphertext.iter());

    OpaqueMessage {
        typ: msg.typ,
        version: msg.version,
        payload: Payload::new(nonce_ct_mac),
    }
}
