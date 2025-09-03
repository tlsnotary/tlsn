use crate::types::received_commitments;

use super::types::ZKProofBundle;
use chrono::{Datelike, NaiveDate};
use noir::barretenberg::verify::{get_ultra_honk_verification_key, verify_ultra_honk};
use serde_json::Value;
use tls_server_fixture::CA_CERT_DER;
use tlsn::{
    config::{CertificateDer, ProtocolConfigValidator, RootCertStore},
    connection::ServerName,
    hash::HashAlgId,
    transcript::{Direction, PartialTranscript},
    verifier::{Verifier, VerifierConfig, VerifierOutput, VerifyConfig},
};
use tlsn_examples::{MAX_RECV_DATA, MAX_SENT_DATA};
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::instrument;
#[instrument(skip(socket, extra_socket))]
pub async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    mut extra_socket: T,
) -> PartialTranscript {
    // Set up Verifier.
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .protocol_config_validator(config_validator)
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    // Receive authenticated data.
    let VerifierOutput {
        server_name,
        transcript,
        transcript_commitments,
        ..
    } = verifier
        .verify(socket.compat(), &VerifyConfig::default())
        .await
        .unwrap();

    let server_name = server_name.expect("prover should have revealed server name");
    let transcript = transcript.expect("prover should have revealed transcript data");

    // Check sent data.
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone()).expect("Verifier expected sent data");
    sent_data
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Verification failed: Expected host {SERVER_DOMAIN}"));

    // Check received data.
    let received_commitments = received_commitments(&transcript_commitments);
    let received_commitment = received_commitments
        .iter()
        .next()
        .expect("missing received hash commitment");

    // dbg!(&received_commitment.direction);

    assert!(received_commitment.direction == Direction::Received);
    // dbg!(&received_commitment.idx);
    assert!(received_commitment.hash.alg == HashAlgId::SHA256);
    let committed_hash = &received_commitment.hash;

    // Check Session info: server name.
    let ServerName::Dns(server_name) = server_name;
    assert_eq!(server_name.as_str(), SERVER_DOMAIN);

    // Receive ZKProof information from prover
    let mut buf = Vec::new();
    extra_socket.read_to_end(&mut buf).await.unwrap();
    let msg: ZKProofBundle = bincode::deserialize(&buf).unwrap();

    // Verify zk proof
    const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");
    let json: Value = serde_json::from_str(PROGRAM_JSON).unwrap();
    let bytecode = json["bytecode"].as_str().unwrap();

    let vk = get_ultra_honk_verification_key(bytecode, false).unwrap();
    assert_eq!(vk, msg.vk);

    // check that the check date is correctly included in the proof
    let check_date =
        NaiveDate::parse_from_str(&msg.check_date, "%Y-%m-%d").expect("invalid date format");

    let proof = msg.proof.clone();

    let check_date_day = u128::from_be_bytes(proof[16..32].try_into().unwrap());
    let check_date_month = u128::from_be_bytes(proof[48..64].try_into().unwrap());
    let check_date_year = u128::from_be_bytes(proof[80..96].try_into().unwrap());

    assert_eq!(check_date_day, check_date.day() as u128);
    assert_eq!(check_date_month, check_date.month() as u128);
    assert_eq!(check_date_year, check_date.year() as u128);

    // check that the committed hash in the proof matches the hash from the
    // commitment
    let committed_hash_in_proof: Vec<u8> = proof
        .chunks(32)
        .skip(3) // skip the first 3 chunks
        .take(32)
        .map(|chunk| *chunk.last().unwrap())
        .collect();
    assert_eq!(
        committed_hash_in_proof,
        committed_hash.value.as_bytes().to_vec()
    );

    if committed_hash_in_proof != committed_hash.value.as_bytes().to_vec() {
        println!("❌ The hash in the proof does not match the committed hash in MPC-TLS");
        println!(
            "{} != {}",
            hex::encode(committed_hash_in_proof.clone()),
            hex::encode(committed_hash.value.as_bytes())
        );
    } else {
        tracing::info!(
            "✅ The hash in the proof matches the committed hash in MPC-TLS ({})",
            hex::encode(committed_hash.value.as_bytes())
        );
    }

    let is_valid = verify_ultra_honk(msg.proof, msg.vk).expect("Verification failed");

    if is_valid {
        tracing::info!("✅ Age verification ZKProof successfully verified");
    } else {
        tracing::error!("❌ Age verification ZKProof failed to verify");
        panic!("Age verification ZKProof failed to verify");
    }

    transcript
}
