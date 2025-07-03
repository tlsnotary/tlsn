//! Attestation fixtures.

use tlsn_core::{
    connection::{HandshakeData, HandshakeDataV1_2},
    fixtures::ConnectionFixture,
    hash::HashAlgorithm,
    transcript::{
        Transcript, TranscriptCommitConfigBuilder, TranscriptCommitment,
        encoding::{EncodingProvider, EncodingTree},
    },
};

use crate::{
    Attestation, AttestationConfig, CryptoProvider, Extension,
    request::{Request, RequestConfig},
    signing::SignatureAlgId,
};

/// Returns a notary signing key fixture.
pub fn notary_signing_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap()
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
        .transcript(transcript);

    let (request, _) = request_builder.build(&provider).unwrap();

    RequestFixture {
        encoding_tree,
        request,
    }
}

/// Returns an attestation fixture for testing.
pub fn attestation_fixture(
    request: Request,
    connection: ConnectionFixture,
    signature_alg: SignatureAlgId,
    transcript_commitments: &[TranscriptCommitment],
) -> Attestation {
    let ConnectionFixture {
        connection_info,
        server_cert_data,
        ..
    } = connection;

    let HandshakeData::V1_2(HandshakeDataV1_2 {
        server_ephemeral_key,
        ..
    }) = server_cert_data.handshake
    else {
        panic!("expected v1.2 handshake data");
    };

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
        .transcript_commitments(transcript_commitments.to_vec());

    attestation_builder.build(&provider).unwrap()
}
