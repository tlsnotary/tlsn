//! Fixtures for testing

mod provider;

pub use provider::ChaChaProvider;

use hex::FromHex;
use p256::ecdsa::SigningKey;

use crate::{
    connection::{
        Certificate, ConnectionInfo, HandshakeData, HandshakeDataV1_2, KeyType, ServerCertData,
        ServerEphemKey, ServerName, ServerSignature, SignatureScheme, TlsVersion, TranscriptLength,
    },
    transcript::{encoding::EncodingProvider, Transcript},
};

/// A fixture containing various TLS connection data.
#[allow(missing_docs)]
pub struct ConnectionFixture {
    pub server_name: ServerName,
    pub connection_info: ConnectionInfo,
    pub server_cert_data: ServerCertData,
}

impl ConnectionFixture {
    /// Returns a connection fixture for tlsnotary.org.
    pub fn tlsnotary(transcript_length: TranscriptLength) -> Self {
        ConnectionFixture {
            server_name: ServerName::new("tlsnotary.org".to_string()),
            connection_info: ConnectionInfo {
                time: 1671637529,
                version: TlsVersion::V1_2,
                transcript_length,
            },
            server_cert_data: ServerCertData {
                certs: vec![
                    Certificate(include_bytes!("fixtures/data/tlsnotary.org/ee.der").to_vec()),
                    Certificate(include_bytes!("fixtures/data/tlsnotary.org/inter.der").to_vec()),
                    Certificate(include_bytes!("fixtures/data/tlsnotary.org/ca.der").to_vec()),
                ],
                sig: ServerSignature {
                    scheme: SignatureScheme::RSA_PKCS1_SHA256,
                    sig: Vec::<u8>::from_hex(include_bytes!(
                        "fixtures/data/tlsnotary.org/signature"
                    ))
                    .unwrap(),
                },
                handshake: HandshakeData::V1_2(HandshakeDataV1_2 {
                    client_random: <[u8; 32]>::from_hex(include_bytes!(
                        "fixtures/data/tlsnotary.org/client_random"
                    ))
                    .unwrap(),
                    server_random: <[u8; 32]>::from_hex(include_bytes!(
                        "fixtures/data/tlsnotary.org/server_random"
                    ))
                    .unwrap(),
                    server_ephemeral_key: ServerEphemKey {
                        typ: KeyType::SECP256R1,
                        key: Vec::<u8>::from_hex(include_bytes!(
                            "fixtures/data/tlsnotary.org/pubkey"
                        ))
                        .unwrap(),
                    },
                }),
            },
        }
    }

    /// Returns a connection fixture for appliedzkp.org.
    pub fn appliedzkp(transcript_length: TranscriptLength) -> Self {
        ConnectionFixture {
            server_name: ServerName::new("appliedzkp.org".to_string()),
            connection_info: ConnectionInfo {
                time: 1671637529,
                version: TlsVersion::V1_2,
                transcript_length,
            },
            server_cert_data: ServerCertData {
                certs: vec![
                    Certificate(include_bytes!("fixtures/data/appliedzkp.org/ee.der").to_vec()),
                    Certificate(include_bytes!("fixtures/data/appliedzkp.org/inter.der").to_vec()),
                    Certificate(include_bytes!("fixtures/data/appliedzkp.org/ca.der").to_vec()),
                ],
                sig: ServerSignature {
                    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                    sig: Vec::<u8>::from_hex(include_bytes!(
                        "fixtures/data/appliedzkp.org/signature"
                    ))
                    .unwrap(),
                },
                handshake: HandshakeData::V1_2(HandshakeDataV1_2 {
                    client_random: <[u8; 32]>::from_hex(include_bytes!(
                        "fixtures/data/appliedzkp.org/client_random"
                    ))
                    .unwrap(),
                    server_random: <[u8; 32]>::from_hex(include_bytes!(
                        "fixtures/data/appliedzkp.org/server_random"
                    ))
                    .unwrap(),
                    server_ephemeral_key: ServerEphemKey {
                        typ: KeyType::SECP256R1,
                        key: Vec::<u8>::from_hex(include_bytes!(
                            "fixtures/data/appliedzkp.org/pubkey"
                        ))
                        .unwrap(),
                    },
                }),
            },
        }
    }

    /// Returns the server_ephemeral_key fixture.
    pub fn server_ephemeral_key(&self) -> &ServerEphemKey {
        let HandshakeData::V1_2(HandshakeDataV1_2 {
            server_ephemeral_key,
            ..
        }) = &self.server_cert_data.handshake;
        server_ephemeral_key
    }
}

/// Returns an encoding provider fixture.
pub fn encoding_provider(tx: &[u8], rx: &[u8]) -> impl EncodingProvider {
    ChaChaProvider::new(encoder_seed(), Transcript::new(tx, rx))
}

/// Returns an encoder seed fixture.
pub fn encoder_seed() -> [u8; 32] {
    [0u8; 32]
}

/// Returns a notary signing key fixture.
pub fn notary_signing_key() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}
