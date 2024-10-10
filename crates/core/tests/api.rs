use tlsn_core::{
    attestation::{Attestation, AttestationConfig},
    connection::{HandshakeData, HandshakeDataV1_2},
    fixtures::{self, encoder_seed, plaintext_hashes_from_request, ConnectionFixture},
    hash::{Blake3, HashAlgId},
    presentation::PresentationOutput,
    request::{Request, RequestConfig},
    signing::SignatureAlgId,
    transcript::{
        encoding::EncodingTree, Direction, Idx, Transcript, TranscriptCommitConfigBuilder,
        TranscriptCommitmentKind,
    },
    CryptoProvider,
};
use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};
use utils::range::{RangeSet, Union};

/// Tests that the attestation protocol and verification work end-to-end.
#[test]
fn test_api() {
    let mut provider = CryptoProvider::default();

    // Configure signer for Notary.
    provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let (sent_len, recv_len) = transcript.len();
    // Plaintext encodings which the Prover obtained from GC evaluation.
    let encodings_provider = fixtures::encoding_provider(GET_WITH_HEADER, OK_JSON);

    // At the end of the TLS connection the Prover holds the:
    let ConnectionFixture {
        server_name,
        connection_info,
        server_cert_data,
    } = ConnectionFixture::tlsnotary(transcript.length());

    let HandshakeData::V1_2(HandshakeDataV1_2 {
        server_ephemeral_key,
        ..
    }) = server_cert_data.handshake.clone()
    else {
        unreachable!()
    };

    // Prover specifies the ranges it wants to commit to.
    let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
    transcript_commitment_builder
        .commit_sent(&(0..sent_len / 2))
        .unwrap()
        .commit_recv(&(0..recv_len / 2))
        .unwrap();

    #[cfg(feature = "use_poseidon_halo2")]
    {
        transcript_commitment_builder.default_kind(TranscriptCommitmentKind::Hash {
            alg: HashAlgId::POSEIDON_HALO2,
        });
        transcript_commitment_builder
            .commit_sent(&(sent_len / 2..sent_len))
            .unwrap()
            .commit_recv(&(recv_len / 2..recv_len))
            .unwrap();
    }

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
        .transcript(transcript)
        .encoding_tree(encoding_tree);

    if transcripts_commitment_config.has_plaintext_hashes() {
        request_builder.plaintext_hashes(transcripts_commitment_config.plaintext_hashes());
    }

    let (request, secrets) = request_builder.build(&provider).unwrap();

    // At this point the Authdecode protocol must be run if there was a commitment algorithm used
    // which requires it. After that, the Notary can proceed to create an attestation.

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    // Notary builds and signs an attestation according to their view of the connection.
    let mut attestation_builder = Attestation::builder(&attestation_config);

    // Optionally, Notary obtains authenticated plaintext hashes from an external context and adds them
    // to the attestation.
    let authenticated_hashes = plaintext_hashes_from_request(&request);
    if !authenticated_hashes.is_empty() {
        attestation_builder.plaintext_hashes(authenticated_hashes);
    }

    let mut attestation_builder = attestation_builder.accept_request(request.clone()).unwrap();

    attestation_builder
        // Notary's view of the connection
        .connection_info(connection_info.clone())
        // Server key Notary received during handshake
        .server_ephemeral_key(server_ephemeral_key)
        .encoding_seed(encoder_seed().to_vec());

    let attestation = attestation_builder.build(&provider).unwrap();

    // Prover validates the attestation is consistent with its request.
    request.validate(&attestation).unwrap();

    let mut transcript_proof_builder = secrets.transcript_proof_builder();

    // Stores the ranges which were revealed for the sent and the received data.
    let mut revealed_sent = RangeSet::default();
    let mut revealed_recv = RangeSet::default();

    transcript_proof_builder
        .reveal(&(0..sent_len / 2), Direction::Sent)
        .unwrap();
    revealed_sent = revealed_sent.union(&(0..sent_len / 2));

    transcript_proof_builder
        .reveal(&(0..recv_len / 2), Direction::Received)
        .unwrap();
    revealed_recv = revealed_recv.union(&(0..recv_len / 2));

    #[cfg(feature = "use_poseidon_halo2")]
    {
        transcript_proof_builder.default_kind(TranscriptCommitmentKind::Hash {
            alg: HashAlgId::POSEIDON_HALO2,
        });
        transcript_proof_builder
            .reveal(&(sent_len / 2..sent_len), Direction::Sent)
            .unwrap();
        revealed_sent = revealed_sent.union(&(sent_len / 2..sent_len));

        transcript_proof_builder
            .reveal(&(recv_len / 2..recv_len), Direction::Received)
            .unwrap();
        revealed_recv = revealed_recv.union(&(recv_len / 2..recv_len));
    }

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
        presented_transcript,
        secrets
            .transcript()
            .to_partial(Idx::new(revealed_sent), Idx::new(revealed_recv))
    );
}
