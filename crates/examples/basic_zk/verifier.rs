use crate::types::received_commitments;

use super::types::ZKProofBundle;
use anyhow::Result;
use chrono::{Local, NaiveDate};
use futures::io::AsyncReadExt as _;
use noir::barretenberg::verify::{get_ultra_honk_verification_key, verify_ultra_honk};
use serde_json::Value;
use tls_server_fixture::CA_CERT_DER;
use tlsn::{
    config::{tls_commit::TlsCommitProtocolConfig, verifier::VerifierConfig},
    connection::ServerName,
    hash::HashAlgId,
    transcript::{Direction, PartialTranscript},
    verifier::VerifierOutput,
    webpki::{CertificateDer, RootCertStore},
    Session,
};
use tlsn_examples::{MAX_RECV_DATA, MAX_SENT_DATA};
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::instrument;

#[instrument(skip(socket))]
pub async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<PartialTranscript> {
    // Create a session with the prover.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()?;
    let verifier = handle.new_verifier(verifier_config)?;

    // Validate the proposed configuration and then run the TLS commitment protocol.
    let verifier = verifier.commit().await?;

    // This is the opportunity to ensure the prover does not attempt to overload the
    // verifier.
    let reject = if let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = verifier.request().protocol()
    {
        if mpc_tls_config.max_sent_data() > MAX_SENT_DATA {
            Some("max_sent_data is too large")
        } else if mpc_tls_config.max_recv_data() > MAX_RECV_DATA {
            Some("max_recv_data is too large")
        } else {
            None
        }
    } else {
        Some("expecting to use MPC-TLS")
    };

    if reject.is_some() {
        verifier.reject(reject).await?;
        return Err(anyhow::anyhow!("protocol configuration rejected"));
    }

    // Runs the TLS commitment protocol to completion.
    let verifier = verifier.accept().await?.run().await?;

    // Validate the proving request and then verify.
    let verifier = verifier.verify().await?;
    let request = verifier.request();

    if !request.server_identity() || request.reveal().is_none() {
        let verifier = verifier
            .reject(Some(
                "expecting to verify the server name and transcript data",
            ))
            .await?;
        verifier.close().await?;
        return Err(anyhow::anyhow!(
            "prover did not reveal the server name and transcript data"
        ));
    }

    let (
        VerifierOutput {
            server_name,
            transcript,
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.accept().await?;

    verifier.close().await?;

    // Close the session and wait for the driver to complete, reclaiming the socket.
    handle.close();
    let mut socket = driver_task.await??;

    let server_name = server_name.expect("server name should be present");
    let transcript = transcript.expect("transcript should be present");

    // Create hash commitment for the date of birth field from the response
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone())
        .map_err(|e| anyhow::anyhow!("Verifier expected valid UTF-8 sent data: {e}"))?;

    if !sent_data.contains(SERVER_DOMAIN) {
        return Err(anyhow::anyhow!(
            "Verification failed: Expected host {SERVER_DOMAIN} not found in sent data"
        ));
    }

    // Check received data.
    let received_commitments = received_commitments(&transcript_commitments);
    let received_commitment = received_commitments
        .first()
        .ok_or_else(|| anyhow::anyhow!("Missing hash commitment"))?;

    assert!(received_commitment.direction == Direction::Received);
    assert!(received_commitment.hash.alg == HashAlgId::SHA256);

    let committed_hash = &received_commitment.hash;

    // Check Session info: server name.
    let ServerName::Dns(server_name) = server_name;
    if server_name.as_str() != SERVER_DOMAIN {
        return Err(anyhow::anyhow!(
            "Server name mismatch: expected {SERVER_DOMAIN}, got {}",
            server_name.as_str()
        ));
    }

    // Receive ZKProof information from prover
    let mut buf = Vec::new();
    socket.read_to_end(&mut buf).await?;

    if buf.is_empty() {
        return Err(anyhow::anyhow!("No ZK proof data received from prover"));
    }

    let msg: ZKProofBundle = bincode::deserialize(&buf)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize ZK proof bundle: {e}"))?;

    // Verify zk proof
    const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");
    let json: Value = serde_json::from_str(PROGRAM_JSON)
        .map_err(|e| anyhow::anyhow!("Failed to parse Noir circuit: {e}"))?;

    let bytecode = json["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Bytecode field missing in noir.json"))?;

    let vk = get_ultra_honk_verification_key(bytecode, false)
        .map_err(|e| anyhow::anyhow!("Failed to get verification key: {e}"))?;

    if vk != msg.vk {
        return Err(anyhow::anyhow!(
            "Verification key mismatch between computed and provided by prover"
        ));
    }

    let proof = msg.proof.clone();

    // Validate proof has enough data.
    // The proof should start with the public inputs:
    // * We expect at least 3 * 32 bytes for the three date fields (day, month,
    //   year)
    // * and 32*32 bytes for the hash
    let min_bytes = (32 + 3) * 32;
    if proof.len() < min_bytes {
        return Err(anyhow::anyhow!(
            "Proof too short: expected at least {min_bytes} bytes, got {}",
            proof.len()
        ));
    }

    // Check that the proof date is correctly included in the proof
    let proof_date_day: u32 = u32::from_be_bytes(proof[28..32].try_into()?);
    let proof_date_month: u32 = u32::from_be_bytes(proof[60..64].try_into()?);
    let proof_date_year: i32 = i32::from_be_bytes(proof[92..96].try_into()?);
    let proof_date_from_proof =
        NaiveDate::from_ymd_opt(proof_date_year, proof_date_month, proof_date_day)
            .ok_or_else(|| anyhow::anyhow!("Invalid proof date in proof"))?;
    let today = Local::now().date_naive();
    if (today - proof_date_from_proof).num_days() < 0 {
        return Err(anyhow::anyhow!(
            "The proof date can only be today or in the past: provided {proof_date_from_proof}, today {today}"
        ));
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
            "❌ The hash in the proof does not match the committed hash: {} != {}",
            hex::encode(&committed_hash_in_proof),
            hex::encode(&expected_hash)
        );
        return Err(anyhow::anyhow!(
            "Hash in proof does not match committed hash"
        ));
    }
    tracing::info!(
        "✅ The hash in the proof matches the committed hash ({})",
        hex::encode(&expected_hash)
    );

    // Finally verify the proof
    let is_valid = verify_ultra_honk(msg.proof, msg.vk)
        .map_err(|e| anyhow::anyhow!("ZKProof Verification failed: {e}"))?;
    if !is_valid {
        tracing::error!("❌ Age verification ZKProof failed to verify");
        return Err(anyhow::anyhow!("Age verification ZKProof failed to verify"));
    }
    tracing::info!("✅ Age verification ZKProof successfully verified");

    Ok(transcript)
}
