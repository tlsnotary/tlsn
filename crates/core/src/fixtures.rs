//! Fixtures for testing

mod provider;
pub mod transcript;

pub use provider::FixtureEncodingProvider;

use hex::FromHex;

use crate::{
    connection::{
        CertBinding, CertBindingV1_2, ConnectionInfo, DnsName, HandshakeData, KeyType,
        ServerEphemKey, ServerName, ServerSignature, SignatureAlgorithm, TlsVersion,
        TranscriptLength,
    },
    transcript::{
        encoding::{EncoderSecret, EncodingProvider},
        Transcript,
    },
    webpki::CertificateDer,
};

/// A fixture containing various TLS connection data.
#[derive(Clone)]
#[allow(missing_docs)]
pub struct ConnectionFixture {
    pub server_name: ServerName,
    pub connection_info: ConnectionInfo,
    pub server_cert_data: HandshakeData,
}

impl ConnectionFixture {
    /// Returns a connection fixture for tlsnotary.org.
    pub fn tlsnotary(transcript_length: TranscriptLength) -> Self {
        ConnectionFixture {
            server_name: ServerName::Dns(DnsName::try_from("tlsnotary.org").unwrap()),
            connection_info: ConnectionInfo {
                time: 1671637529,
                version: TlsVersion::V1_2,
                transcript_length,
            },
            server_cert_data: HandshakeData {
                certs: vec![
                    CertificateDer(include_bytes!("fixtures/data/tlsnotary.org/ee.der").to_vec()),
                    CertificateDer(
                        include_bytes!("fixtures/data/tlsnotary.org/inter.der").to_vec(),
                    ),
                    CertificateDer(include_bytes!("fixtures/data/tlsnotary.org/ca.der").to_vec()),
                ],
                sig: ServerSignature {
                    alg: SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256,
                    sig: Vec::<u8>::from_hex(include_bytes!(
                        "fixtures/data/tlsnotary.org/signature"
                    ))
                    .unwrap(),
                },
                binding: CertBinding::V1_2(CertBindingV1_2 {
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
            server_name: ServerName::Dns(DnsName::try_from("appliedzkp.org").unwrap()),
            connection_info: ConnectionInfo {
                time: 1671637529,
                version: TlsVersion::V1_2,
                transcript_length,
            },
            server_cert_data: HandshakeData {
                certs: vec![
                    CertificateDer(include_bytes!("fixtures/data/appliedzkp.org/ee.der").to_vec()),
                    CertificateDer(
                        include_bytes!("fixtures/data/appliedzkp.org/inter.der").to_vec(),
                    ),
                    CertificateDer(include_bytes!("fixtures/data/appliedzkp.org/ca.der").to_vec()),
                ],
                sig: ServerSignature {
                    alg: SignatureAlgorithm::ECDSA_NISTP256_SHA256,
                    sig: Vec::<u8>::from_hex(include_bytes!(
                        "fixtures/data/appliedzkp.org/signature"
                    ))
                    .unwrap(),
                },
                binding: CertBinding::V1_2(CertBindingV1_2 {
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
        let CertBinding::V1_2(CertBindingV1_2 {
            server_ephemeral_key,
            ..
        }) = &self.server_cert_data.binding;
        server_ephemeral_key
    }
}

/// Returns an encoding provider fixture.
pub fn encoding_provider(tx: &[u8], rx: &[u8]) -> impl EncodingProvider {
    let secret = encoder_secret();
    FixtureEncodingProvider::new(&secret, Transcript::new(tx, rx))
}

/// Seed fixture.
const SEED: [u8; 32] = [0; 32];

/// Delta fixture.
const DELTA: [u8; 16] = [1; 16];

/// Returns an encoder secret fixture.
pub fn encoder_secret() -> EncoderSecret {
    EncoderSecret::new(SEED, DELTA)
}

/// Returns a tampered encoder secret fixture.
pub fn encoder_secret_tampered_seed() -> EncoderSecret {
    let mut seed = SEED;
    seed[0] += 1;
    EncoderSecret::new(seed, DELTA)
}
