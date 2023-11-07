//! Fixtures for testing

/// Certificate fixtures
pub mod cert;

use std::collections::HashMap;

use hex::FromHex;
use mpz_circuits::types::ValueType;
use mpz_core::{commit::HashCommit, hash::Hash, utils::blake3};
use mpz_garble_core::{ChaChaEncoder, Encoder};
use tls_core::{
    cert::ServerCertDetails,
    handshake::HandshakeData,
    ke::ServerKxDetails,
    key::{Certificate, PublicKey},
    msgs::{
        codec::Codec,
        enums::{NamedGroup, SignatureScheme},
        handshake::{DigitallySignedStruct, Random, ServerECDHParams},
    },
};

use p256::ecdsa::SigningKey;

use crate::{
    merkle::MerkleRoot,
    session::{HandshakeSummary, SessionHeader},
    EncodingProvider,
};

fn value_id(id: &str) -> u64 {
    let hash = blake3(id.as_bytes());
    u64::from_be_bytes(hash[..8].try_into().unwrap())
}

/// Returns a session header fixture using the given transcript lengths and merkle root.
///
/// # Arguments
///
/// * `root` - The merkle root of the transcript commitments.
/// * `sent_len` - The length of the sent transcript.
/// * `recv_len` - The length of the received transcript.
pub fn session_header(root: MerkleRoot, sent_len: usize, recv_len: usize) -> SessionHeader {
    SessionHeader::new(
        encoder_seed(),
        root,
        sent_len,
        recv_len,
        handshake_summary(),
    )
}

/// Returns an encoding provider fixture using the given transcripts.
pub fn encoding_provider(transcript_tx: &[u8], transcript_rx: &[u8]) -> EncodingProvider {
    let encoder = encoder();
    let mut active_encodings = HashMap::new();
    for (idx, byte) in transcript_tx.iter().enumerate() {
        let id = format!("tx/{idx}");
        let enc = encoder.encode_by_type(value_id(&id), &ValueType::U8);
        active_encodings.insert(id, enc.select(*byte).unwrap());
    }
    for (idx, byte) in transcript_rx.iter().enumerate() {
        let id = format!("rx/{idx}");
        let enc = encoder.encode_by_type(value_id(&id), &ValueType::U8);
        active_encodings.insert(id, enc.select(*byte).unwrap());
    }

    Box::new(move |ids: &[&str]| {
        ids.iter()
            .map(|id| active_encodings.get(*id).cloned())
            .collect()
    })
}

/// Returns a handshake summary fixture.
pub fn handshake_summary() -> HandshakeSummary {
    HandshakeSummary::new(1671637529, server_ephemeral_key(), handshake_commitment())
}

/// Returns a handshake commitment fixture.
pub fn handshake_commitment() -> Hash {
    let (_, hash) = handshake_data().hash_commit();
    hash
}

/// Returns a handshake data fixture.
pub fn handshake_data() -> HandshakeData {
    HandshakeData::new(
        server_cert_details(),
        server_kx_details(),
        client_random(),
        server_random(),
    )
}

/// Returns a server certificate details fixture.
pub fn server_cert_details() -> ServerCertDetails {
    ServerCertDetails::new(
        vec![
            Certificate(include_bytes!("testdata/key_exchange/tlsnotary.org/ee.der").to_vec()),
            Certificate(include_bytes!("testdata/key_exchange/tlsnotary.org/inter.der").to_vec()),
            Certificate(include_bytes!("testdata/key_exchange/tlsnotary.org/ca.der").to_vec()),
        ],
        vec![],
        None,
    )
}

/// Returns a server key exchange details fixture.
pub fn server_kx_details() -> ServerKxDetails {
    let mut params = Vec::new();
    let ecdh_params = ServerECDHParams::new(NamedGroup::secp256r1, &server_ephemeral_key().key);
    ecdh_params.encode(&mut params);

    ServerKxDetails::new(
        params,
        DigitallySignedStruct::new(
            SignatureScheme::RSA_PKCS1_SHA256,
            Vec::<u8>::from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/signature"
            ))
            .unwrap(),
        ),
    )
}

/// Returns a client random fixture.
pub fn client_random() -> Random {
    Random(
        <[u8; 32]>::from_hex(include_bytes!(
            "testdata/key_exchange/tlsnotary.org/client_random"
        ))
        .unwrap(),
    )
}

/// Returns a server random fixture.
pub fn server_random() -> Random {
    Random(
        <[u8; 32]>::from_hex(include_bytes!(
            "testdata/key_exchange/tlsnotary.org/server_random"
        ))
        .unwrap(),
    )
}

/// Returns an encoder fixture.
pub fn encoder() -> ChaChaEncoder {
    ChaChaEncoder::new(encoder_seed())
}

/// Returns an encoder seed fixture.
pub fn encoder_seed() -> [u8; 32] {
    [0u8; 32]
}

/// Returns a server ephemeral key fixture.
pub fn server_ephemeral_key() -> PublicKey {
    PublicKey::new(
        NamedGroup::secp256r1,
        &Vec::<u8>::from_hex(include_bytes!("testdata/key_exchange/tlsnotary.org/pubkey")).unwrap(),
    )
}

/// Returns a notary signing key fixture.
pub fn notary_signing_key() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}
