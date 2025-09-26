use crate::types::received_commitments;

use super::types::ZKProofBundle;
use chrono::{Local, NaiveDate};
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
) -> Result<PartialTranscript, Box<dyn std::error::Error>> {
    // Set up Verifier.
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;

    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .protocol_config_validator(config_validator)
        .build()?;

    let verifier = Verifier::new(verifier_config);

    // Receive authenticated data.
    let VerifierOutput {
        server_name,
        transcript,
        transcript_commitments,
        ..
    } = verifier
        .verify(socket.compat(), &VerifyConfig::default())
        .await?;

    let server_name = server_name.ok_or("Prover should have revealed server name")?;
    let transcript = transcript.ok_or("Prover should have revealed transcript data")?;

    // Create hash commitment for the date of birth field from the response
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone())
        .map_err(|e| format!("Verifier expected valid UTF-8 sent data: {}", e))?;

    if !sent_data.contains(SERVER_DOMAIN) {
        return Err(format!(
            "Verification failed: Expected host {} not found in sent data",
            SERVER_DOMAIN
        )
        .into());
    }

    // Check received data.
    let received_commitments = received_commitments(&transcript_commitments);
    let received_commitment = received_commitments
        .first()
        .ok_or("Missing received hash commitment")?;

    assert!(received_commitment.direction == Direction::Received);
    assert!(received_commitment.hash.alg == HashAlgId::BLAKE3);

    let committed_hash = &received_commitment.hash;

    // Check Session info: server name.
    let ServerName::Dns(server_name) = server_name;
    if server_name.as_str() != SERVER_DOMAIN {
        return Err(format!(
            "Server name mismatch: expected {}, got {}",
            SERVER_DOMAIN,
            server_name.as_str()
        )
        .into());
    }

    // Receive ZKProof information from prover
    let mut buf = Vec::new();
    extra_socket.read_to_end(&mut buf).await?;

    if buf.is_empty() {
        return Err("No ZK proof data received from prover".into());
    }

    let msg: ZKProofBundle = bincode::deserialize(&buf)
        .map_err(|e| format!("Failed to deserialize ZK proof bundle: {}", e))?;

    // Verify zk proof
    const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");
    let json: Value = serde_json::from_str(PROGRAM_JSON)
        .map_err(|e| format!("Failed to parse Noir circuit: {}", e))?;

    let bytecode = json["bytecode"]
        .as_str()
        .ok_or("Bytecode field missing in noir.json")?;

    let vk = get_ultra_honk_verification_key(bytecode, false)
        .map_err(|e| format!("Failed to get verification key: {}", e))?;

    if vk != msg.vk {
        return Err("Verification key mismatch between computed and provided by prover".into());
    }

    let proof = msg.proof.clone();

    // Validate proof has enough data.
    // The proof should start with the public inputs:
    // * We expect at least 3 * 32 bytes for the three date fields (day, month,
    //   year)
    // * and 32*32 bytes for the hash
    let min_bytes = (32 + 3) * 32;
    if proof.len() < min_bytes {
        return Err(format!(
            "Proof too short: expected at least {} bytes, got {}",
            min_bytes,
            proof.len()
        )
        .into());
    }

    // Check that the proof date is correctly included in the proof
    let proof_date_day: u32 = u32::from_be_bytes(proof[28..32].try_into()?);
    let proof_date_month: u32 = u32::from_be_bytes(proof[60..64].try_into()?);
    let proof_date_year: i32 = i32::from_be_bytes(proof[92..96].try_into()?);
    let proof_date_from_proof =
        NaiveDate::from_ymd_opt(proof_date_year, proof_date_month, proof_date_day)
            .ok_or("Invalid proof date in proof")?;
    let today = Local::now().date_naive();
    if (today - proof_date_from_proof).num_days() < 0 {
        return Err(format!(
            "The proof date can only be today or in the past: provided {}, today {}",
            proof_date_from_proof, today
        )
        .into());
    }

    // Check that the committed hash in the proof matches the hash from the
    // commitment
    let committed_hash_in_proof: Vec<u8> = proof
        .chunks(32)
        .skip(3) // skip the first 3 chunks
        .take(32)
        .map(|chunk| *chunk.last().unwrap_or(&0))
        .collect();
    let expected_hash = committed_hash.value.as_bytes().to_vec();
    if committed_hash_in_proof != expected_hash {
        tracing::error!(
            "❌ The hash in the proof does not match the committed hash in MPC-TLS: {} != {}",
            hex::encode(&committed_hash_in_proof),
            hex::encode(&expected_hash)
        );
        return Err("Hash in proof does not match committed hash in MPC-TLS".into());
    }
    tracing::info!(
        "✅ The hash in the proof matches the committed hash in MPC-TLS ({})",
        hex::encode(&expected_hash)
    );

    // Finally verify the proof
    let is_valid = verify_ultra_honk(msg.proof, msg.vk)
        .map_err(|e| format!("ZKProof Verification failed: {}", e))?;
    if !is_valid {
        tracing::error!("❌ Age verification ZKProof failed to verify");
        return Err("Age verification ZKProof failed to verify".into());
    }
    tracing::info!("✅ Age verification ZKProof successfully verified");

    Ok(transcript)
}
