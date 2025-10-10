use tlsn_attestation::{
    Attestation, AttestationConfig, CryptoProvider,
    presentation::PresentationOutput,
    request::{Request, RequestConfig},
    signing::SignatureAlgId,
};
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2},
    fixtures::{self, ConnectionFixture, encoder_secret},
    hash::Blake3,
    transcript::{
        Direction, Transcript, TranscriptCommitConfigBuilder, TranscriptCommitment,
        TranscriptSecret,
        encoding::{EncodingCommitment, EncodingTree},
    },
};
use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

/// Tests that the attestation protocol and verification work end-to-end
#[test]
fn test_api() {
    let mut provider = CryptoProvider::default();

    // Configure signer for Notary
    provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let (sent_len, recv_len) = transcript.len();
    // Plaintext encodings which the Prover obtained from GC evaluation
    let encodings_provider = fixtures::encoding_provider(GET_WITH_HEADER, OK_JSON);

    // At the end of the TLS connection the Prover holds the:
    let ConnectionFixture {
        server_name,
        connection_info,
        server_cert_data,
    } = ConnectionFixture::tlsnotary(transcript.length());

    let CertBinding::V1_2(CertBindingV1_2 {
        server_ephemeral_key,
        ..
    }) = server_cert_data.binding.clone()
    else {
        unreachable!()
    };

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
    )
    .unwrap();

    let encoding_commitment = EncodingCommitment {
        root: encoding_tree.root(),
    };

    let request_config = RequestConfig::default();
    let mut request_builder = Request::builder(&request_config);

    request_builder
        .server_name(server_name.clone())
        .handshake_data(server_cert_data)
        .transcript(transcript)
        .transcript_commitments(
            vec![TranscriptSecret::Encoding(encoding_tree)],
            vec![TranscriptCommitment::Encoding(encoding_commitment.clone())],
        );

    let (request, secrets) = request_builder.build(&provider).unwrap();

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    // Notary signs an attestation according to their view of the connection.
    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request.clone())
        .unwrap();

    attestation_builder
        // Notary's view of the connection
        .connection_info(connection_info.clone())
        // Server key Notary received during handshake
        .server_ephemeral_key(server_ephemeral_key)
        .encoder_secret(encoder_secret())
        .transcript_commitments(vec![TranscriptCommitment::Encoding(encoding_commitment)]);

    let attestation = attestation_builder.build(&provider).unwrap();

    // Prover validates the attestation is consistent with its request.
    request.validate(&attestation).unwrap();

    let mut transcript_proof_builder = secrets.transcript_proof_builder();

    transcript_proof_builder
        .reveal(&(0..sent_len), Direction::Sent)
        .unwrap();
    transcript_proof_builder
        .reveal(&(0..recv_len), Direction::Received)
        .unwrap();

    let transcript_proof = transcript_proof_builder.build().unwrap();

    let mut builder = attestation.presentation_builder(&provider);

    builder.identity_proof(secrets.identity_proof());
    builder.transcript_proof(transcript_proof);

    let presentation = builder.build().unwrap();

    // Verifier verifies the presentation.
    let PresentationOutput {
        server_name: presented_server_name,
        connection_info: presented_connection_info,
        transcript: presented_transcript,
        ..
    } = presentation.verify(&provider).unwrap();

    assert_eq!(presented_server_name.unwrap(), server_name);
    assert_eq!(presented_connection_info, connection_info);

    let presented_transcript = presented_transcript.unwrap();

    assert_eq!(
        presented_transcript.sent_unsafe(),
        secrets.transcript().sent()
    );
    assert_eq!(
        presented_transcript.received_unsafe(),
        secrets.transcript().received()
    );
}
