use rand::{Rng, SeedableRng, rngs::StdRng};
use rangeset::set::RangeSet;
use tlsn_attestation::{
    Attestation, AttestationConfig, CryptoProvider,
    presentation::PresentationOutput,
    request::{Request, RequestConfig},
    signing::SignatureAlgId,
};
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2},
    fixtures::ConnectionFixture,
    hash::{Blake3, Blinder, HashAlgId},
    transcript::{
        Direction, Transcript, TranscriptCommitment, TranscriptSecret,
        hash::{PlaintextHash, PlaintextHashSecret, hash_plaintext},
    },
};
use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

/// Tests that the attestation protocol and verification work end-to-end
#[test]
fn test_api() {
    let mut rng = StdRng::seed_from_u64(0);
    let mut provider = CryptoProvider::default();

    // Configure signer for Notary
    provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let (sent_len, recv_len) = transcript.len();

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

    // Create hash commitments
    let hasher = Blake3::default();
    let sent_blinder: Blinder = rng.random();
    let recv_blinder: Blinder = rng.random();

    let sent_idx = RangeSet::from(0..sent_len);
    let recv_idx = RangeSet::from(0..recv_len);

    let sent_hash_commitment = PlaintextHash {
        direction: Direction::Sent,
        idx: sent_idx.clone(),
        hash: hash_plaintext(&hasher, transcript.sent(), &sent_blinder),
    };

    let recv_hash_commitment = PlaintextHash {
        direction: Direction::Received,
        idx: recv_idx.clone(),
        hash: hash_plaintext(&hasher, transcript.received(), &recv_blinder),
    };

    let sent_hash_secret = PlaintextHashSecret {
        direction: Direction::Sent,
        idx: sent_idx,
        alg: HashAlgId::BLAKE3,
        blinder: sent_blinder,
    };

    let recv_hash_secret = PlaintextHashSecret {
        direction: Direction::Received,
        idx: recv_idx,
        alg: HashAlgId::BLAKE3,
        blinder: recv_blinder,
    };

    let request_config = RequestConfig::default();
    let mut request_builder = Request::builder(&request_config);

    request_builder
        .server_name(server_name.clone())
        .handshake_data(server_cert_data)
        .transcript(transcript)
        .transcript_commitments(
            vec![
                TranscriptSecret::Hash(sent_hash_secret),
                TranscriptSecret::Hash(recv_hash_secret),
            ],
            vec![
                TranscriptCommitment::Hash(sent_hash_commitment.clone()),
                TranscriptCommitment::Hash(recv_hash_commitment.clone()),
            ],
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
        .transcript_commitments(vec![
            TranscriptCommitment::Hash(sent_hash_commitment),
            TranscriptCommitment::Hash(recv_hash_commitment),
        ]);

    let attestation = attestation_builder.build(&provider).unwrap();

    // Prover validates the attestation is consistent with its request.
    request.validate(&attestation, &provider).unwrap();

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
