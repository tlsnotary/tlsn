//! Fixtures for testing

/// Certificate fixtures
pub mod cert;
mod provider;

use bytes::Bytes;
pub use provider::ChaChaProvider;

use std::collections::HashMap;

use hex::FromHex;
use mpz_circuits::types::ValueType;
use mpz_core::{commit::HashCommit, hash::Hash, utils::blake3};
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
    attestation::AttestationFull,
    encoding::{new_encoder, Encoder, EncodingProvider},
    Transcript,
};

/// Returns an attestation fixture.
pub fn attestation() -> AttestationFull {
    todo!()
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
pub(crate) fn encoder() -> impl Encoder {
    new_encoder(encoder_seed())
}

pub fn provider(tx: &[u8], rx: &[u8]) -> impl EncodingProvider {
    ChaChaProvider::new(
        encoder_seed(),
        Transcript::new(Bytes::copy_from_slice(tx)),
        Transcript::new(Bytes::copy_from_slice(rx)),
    )
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
