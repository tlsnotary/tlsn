//! Prover that creates a presentation and sends it over TCP.
//! Compiled with normal getrandom.

use std::io::Write;
use std::net::TcpListener;

use tlsn_attestation::{
    Attestation, AttestationConfig, CryptoProvider,
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

fn main() {
    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let (sent_len, recv_len) = transcript.len();
    let encodings_provider = fixtures::encoding_provider(GET_WITH_HEADER, OK_JSON);

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

    let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
    transcript_commitment_builder
        .commit_sent(&(0..sent_len))
        .unwrap()
        .commit_recv(&(0..recv_len))
        .unwrap();

    let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

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

    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request.clone())
        .unwrap();

    attestation_builder
        .connection_info(connection_info.clone())
        .server_ephemeral_key(server_ephemeral_key)
        .encoder_secret(encoder_secret())
        .transcript_commitments(vec![TranscriptCommitment::Encoding(encoding_commitment)]);

    let attestation = attestation_builder.build(&provider).unwrap();
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

    // Serialize presentation
    let presentation_bytes = bincode::serialize(&presentation).unwrap();

    // Send over TCP
    let listener = TcpListener::bind("127.0.0.1:19844").unwrap();
    println!("Prover listening on 127.0.0.1:19844");
    println!("Presentation size: {} bytes", presentation_bytes.len());

    let (mut stream, _) = listener.accept().unwrap();
    println!("Verifier connected, sending presentation...");

    // Send length first, then data
    let len = presentation_bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).unwrap();
    stream.write_all(&presentation_bytes).unwrap();
    stream.flush().unwrap();

    println!("Presentation sent successfully");
}
