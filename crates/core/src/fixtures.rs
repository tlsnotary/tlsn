//! Fixtures for testing

mod provider;

pub use provider::FixtureEncodingProvider;

use hex::FromHex;
use p256::ecdsa::SigningKey;
use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

use crate::{
    attestation::{Attestation, AttestationConfig, Extension},
    connection::{
        Certificate, ConnectionInfo, HandshakeData, HandshakeDataV1_2, KeyType, ServerCertData,
        ServerEphemKey, ServerName, ServerSignature, SignatureScheme, TlsVersion, TranscriptLength,
    },
    hash::{Blake3, HashAlgorithm},
    request::{Request, RequestConfig},
    signing::SignatureAlgId,
    transcript::{
        encoding::{EncoderSecret, EncodingProvider, EncodingTree},
        Transcript, TranscriptCommitConfigBuilder,
    },
    CryptoProvider,
};

/// A fixture containing various TLS connection data.
#[derive(Clone)]
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

/// Returns a notary signing key fixture.
pub fn notary_signing_key() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}

/// A Request fixture used for testing.
#[allow(missing_docs)]
pub struct RequestFixture {
    pub encoding_tree: EncodingTree,
    pub request: Request,
}

/// Returns a request fixture for testing.
pub fn request_fixture(
    transcript: Transcript,
    encodings_provider: impl EncodingProvider,
    connection: ConnectionFixture,
    encoding_hasher: impl HashAlgorithm,
    extensions: Vec<Extension>,
) -> RequestFixture {
    let provider = CryptoProvider::default();
    let (sent_len, recv_len) = transcript.len();

    let ConnectionFixture {
        server_name,
        server_cert_data,
        ..
    } = connection;

    let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
    transcript_commitment_builder
        .commit_sent(&(0..sent_len))
        .unwrap()
        .commit_recv(&(0..recv_len))
        .unwrap();
    let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

    // Prover constructs encoding tree.
    let encoding_tree = EncodingTree::new(
        &encoding_hasher,
        transcripts_commitment_config.iter_encoding(),
        &encodings_provider,
        &transcript.length(),
    )
    .unwrap();

    let mut builder = RequestConfig::builder();

    for extension in extensions {
        builder.extension(extension);
    }

    let request_config = builder.build().unwrap();

    let mut request_builder = Request::builder(&request_config);
    request_builder
        .server_name(server_name)
        .server_cert_data(server_cert_data)
        .transcript(transcript)
        .encoding_tree(encoding_tree.clone());

    let (request, _) = request_builder.build(&provider).unwrap();

    RequestFixture {
        encoding_tree,
        request,
    }
}

/// Returns an attestation fixture and a crypto provider for testing.
pub fn attestation_fixture(
    request: Request,
    connection: ConnectionFixture,
    signature_alg: SignatureAlgId,
    secret: EncoderSecret,
) -> (Attestation, CryptoProvider) {
    let ConnectionFixture {
        connection_info,
        server_cert_data,
        ..
    } = connection;

    let HandshakeData::V1_2(HandshakeDataV1_2 {
        server_ephemeral_key,
        ..
    }) = server_cert_data.handshake;

    let mut provider = CryptoProvider::default();
    match signature_alg {
        SignatureAlgId::SECP256K1 => provider.signer.set_secp256k1(&[42u8; 32]).unwrap(),
        SignatureAlgId::SECP256R1 => provider.signer.set_secp256r1(&[42u8; 32]).unwrap(),
        _ => unimplemented!(),
    };

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([signature_alg])
        .build()
        .unwrap();

    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request)
        .unwrap();

    attestation_builder
        .connection_info(connection_info)
        .server_ephemeral_key(server_ephemeral_key)
        .encoder_secret(secret);

    (attestation_builder.build(&provider).unwrap(), provider)
}

/// Returns a basic attestation fixture and a crypto provider for testing.
pub fn basic_attestation_fixture() -> (Attestation, CryptoProvider) {
    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let connection = ConnectionFixture::tlsnotary(transcript.length());

    let RequestFixture {
        mut request,
        encoding_tree: _,
    } = request_fixture(
        transcript.clone(),
        encoding_provider(GET_WITH_HEADER, OK_JSON),
        connection.clone(),
        Blake3::default(),
        Vec::new(),
    );

    request.encoding_commitment_root = None;
    attestation_fixture(
        request,
        connection,
        SignatureAlgId::SECP256K1,
        encoder_secret(),
    )
}
