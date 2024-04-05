//! Fixtures for testing

mod provider;

pub use provider::ChaChaProvider;

use hex::FromHex;
use p256::ecdsa::SigningKey;

use crate::{
    conn::{
        Certificate, CertificateData, ConnectionInfo, HandshakeData, HandshakeDataV1_2, KeyType,
        ServerEphemKey, ServerIdentity, ServerSignature, SignatureScheme, TlsVersion,
        TranscriptLength,
    },
    encoding::{new_encoder, Encoder, EncodingProvider},
    Transcript,
};

/// A fixture containing various TLS connection data.
pub struct ConnectionFixture {
    /// The server identity.
    pub server_identity: ServerIdentity,
    /// The connection information.
    pub connection_info: ConnectionInfo,
    /// The handshake data.
    pub handshake_data: HandshakeData,
    /// The certificate data.
    pub certificate_data: CertificateData,
}

impl ConnectionFixture {
    /// Returns a connection fixture for tlsnotary.org.
    pub fn tlsnotary(transcript_length: TranscriptLength) -> Self {
        ConnectionFixture {
            server_identity: ServerIdentity::new("tlsnotary.org".to_string()),
            connection_info: ConnectionInfo {
                time: 1671637529,
                version: TlsVersion::V1_2,
                transcript_length,
            },
            handshake_data: HandshakeData::V1_2(HandshakeDataV1_2 {
                client_random: <[u8; 32]>::from_hex(include_bytes!(
                    "data/tlsnotary.org/client_random"
                ))
                .unwrap(),
                server_random: <[u8; 32]>::from_hex(include_bytes!(
                    "data/tlsnotary.org/server_random"
                ))
                .unwrap(),
                server_ephemeral_key: ServerEphemKey {
                    typ: KeyType::Secp256r1,
                    key: Vec::<u8>::from_hex(include_bytes!("data/tlsnotary.org/pubkey")).unwrap(),
                },
            }),
            certificate_data: CertificateData {
                certs: vec![
                    Certificate(include_bytes!("data/tlsnotary.org/ee.der").to_vec()),
                    Certificate(include_bytes!("data/tlsnotary.org/inter.der").to_vec()),
                    Certificate(include_bytes!("data/tlsnotary.org/ca.der").to_vec()),
                ],
                sig: ServerSignature {
                    scheme: SignatureScheme::RSA_PKCS1_SHA256,
                    sig: Vec::<u8>::from_hex(include_bytes!("data/tlsnotary.org/signature"))
                        .unwrap(),
                },
            },
        }
    }

    /// Returns a connection fixture for appliedzkp.org.
    pub fn appliedzkp(transcript_length: TranscriptLength) -> Self {
        ConnectionFixture {
            server_identity: ServerIdentity::new("appliedzkp.org".to_string()),
            connection_info: ConnectionInfo {
                time: 1671637529,
                version: TlsVersion::V1_2,
                transcript_length,
            },
            handshake_data: HandshakeData::V1_2(HandshakeDataV1_2 {
                client_random: <[u8; 32]>::from_hex(include_bytes!(
                    "data/appliedzkp.org/client_random"
                ))
                .unwrap(),
                server_random: <[u8; 32]>::from_hex(include_bytes!(
                    "data/appliedzkp.org/server_random"
                ))
                .unwrap(),
                server_ephemeral_key: ServerEphemKey {
                    typ: KeyType::Secp256r1,
                    key: Vec::<u8>::from_hex(include_bytes!("data/appliedzkp.org/pubkey")).unwrap(),
                },
            }),
            certificate_data: CertificateData {
                certs: vec![
                    Certificate(include_bytes!("data/appliedzkp.org/ee.der").to_vec()),
                    Certificate(include_bytes!("data/appliedzkp.org/inter.der").to_vec()),
                    Certificate(include_bytes!("data/appliedzkp.org/ca.der").to_vec()),
                ],
                sig: ServerSignature {
                    scheme: SignatureScheme::RSA_PKCS1_SHA256,
                    sig: Vec::<u8>::from_hex(include_bytes!("data/appliedzkp.org/signature"))
                        .unwrap(),
                },
            },
        }
    }
}

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
