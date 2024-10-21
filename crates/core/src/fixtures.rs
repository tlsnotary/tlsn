//! Fixtures for testing

mod provider;

pub use provider::ChaChaProvider;

use hex::FromHex;
use p256::ecdsa::SigningKey;
use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

use crate::{
    attestation::{Attestation, AttestationConfig},
    connection::{
        Certificate, ConnectionInfo, HandshakeData, HandshakeDataV1_2, KeyType, ServerCertData,
        ServerEphemKey, ServerName, ServerSignature, SignatureScheme, TlsVersion, TranscriptLength,
    },
    hash::Blake3,
    request::{Request, RequestConfig},
    signing::SignatureAlgId,
    transcript::{
        encoding::{EncodingProvider, EncodingTree},
        Transcript, TranscriptCommitConfigBuilder,
    },
    CryptoProvider,
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

/// A standard fixture used by different unit tests.
#[allow(missing_docs)]
pub struct TestFixture {
    pub transcript: Transcript,
    pub encoding_tree: EncodingTree,
    pub request: Request,
    pub connection: ConnectionFixture,
}

/// Returns a test fixture.
pub fn test_fixture() -> TestFixture {
    let provider = CryptoProvider::default();

    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let transcript_length = transcript.length();
    let (sent_len, recv_len) = transcript.len();
    // Plaintext encodings which the Prover obtained from GC evaluation
    let encodings_provider = encoding_provider(GET_WITH_HEADER, OK_JSON);

    // At the end of the TLS connection the Prover holds the:
    let ConnectionFixture {
        server_name,
        server_cert_data,
        ..
    } = ConnectionFixture::tlsnotary(transcript.length());

    // Prover specifies the ranges it wants to commit to.
    let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
    transcript_commitment_builder
        .commit_sent(&(0..sent_len))
        .unwrap()
        .commit_recv(&(0..recv_len))
        .unwrap();

    let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

    // Prover constructs encoding tree.
    let encoding_tree = EncodingTree::new(
        &Blake3::default(),
        transcripts_commitment_config.iter_encoding(),
        &encodings_provider,
        &transcript.length(),
    )
    .unwrap();

    let request_config = RequestConfig::default();
    let mut request_builder = Request::builder(&request_config);

    request_builder
        .server_name(server_name.clone())
        .server_cert_data(server_cert_data)
        .transcript(transcript.clone())
        .encoding_tree(encoding_tree.clone());
    let (request, _) = request_builder.build(&provider).unwrap();

    TestFixture {
        transcript,
        encoding_tree,
        request,
        connection: ConnectionFixture::tlsnotary(transcript_length),
    }
}

/// Returns an attestation fixture for unit tests.
pub fn attestation_fixture(payload: (Request, ConnectionFixture)) -> Attestation {
    let (request, connection) = payload;

    let ConnectionFixture {
        connection_info,
        server_cert_data,
        ..
    } = connection;

    let HandshakeData::V1_2(HandshakeDataV1_2 {
        server_ephemeral_key,
        ..
    }) = server_cert_data.handshake.clone();

    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request.clone())
        .unwrap();

    attestation_builder
        .connection_info(connection_info.clone())
        .server_ephemeral_key(server_ephemeral_key)
        .encoding_seed(encoder_seed().to_vec());

    attestation_builder.build(&provider).unwrap()
}
