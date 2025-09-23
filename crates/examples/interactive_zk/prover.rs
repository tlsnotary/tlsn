use std::net::SocketAddr;

use crate::types::received_commitments;

use super::types::ZKProofBundle;

use chrono::{Datelike, Local, NaiveDate};
use http_body_util::Empty;
use hyper::{body::Bytes, header, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use k256::sha2::{Digest, Sha256};
use noir::{
    barretenberg::{
        prove::prove_ultra_honk, srs::setup_srs_from_bytecode,
        verify::get_ultra_honk_verification_key,
    },
    witness::from_vec_str_to_witness_map,
};
use serde_json::Value;
use spansy::{
    http::{BodyContent, Requests, Responses},
    Spanned,
};
use tls_server_fixture::CA_CERT_DER;
use tlsn::{
    config::{CertificateDer, ProtocolConfig, RootCertStore},
    connection::ServerName,
    hash::HashAlgId,
    prover::{ProveConfig, ProveConfigBuilder, Prover, ProverConfig, TlsConfig},
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        Direction, TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitmentKind,
        TranscriptSecret,
    },
};

use tlsn_examples::MAX_RECV_DATA;
use tokio::io::AsyncWriteExt;

use tlsn_examples::MAX_SENT_DATA;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

#[instrument(skip(verifier_socket, verifier_extra_socket))]
pub async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    mut verifier_extra_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let uri = uri.parse::<Uri>()?;

    if uri.scheme().map(|s| s.as_str()) != Some("https") {
        return Err("URI must use HTTPS scheme".into());
    }

    let server_domain = uri.authority().ok_or("URI must have authority")?.host();

    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    let mut tls_config_builder = TlsConfig::builder();
    tls_config_builder.root_store(RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    });
    let tls_config = tls_config_builder.build()?;

    // Set up protocol configuration for prover.
    let mut prover_config_builder = ProverConfig::builder();
    prover_config_builder
        .server_name(ServerName::Dns(server_domain.try_into()?))
        .tls_config(tls_config)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        );

    let prover_config = prover_config_builder.build()?;

    // Create prover and connect to verifier.
    //
    // Perform the setup phase with the verifier.
    let prover = Prover::new(prover_config)
        .setup(verifier_socket.compat())
        .await?;

    // Connect to TLS Server.
    let tls_client_socket = tokio::net::TcpStream::connect(server_addr).await?;

    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) = prover.connect(tls_client_socket.compat()).await?;

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header(header::AUTHORIZATION, "Bearer random_auth_token")
        .method("GET")
        .body(Empty::<Bytes>::new())?;

    let response = request_sender.send_request(request).await?;

    if response.status() != StatusCode::OK {
        return Err(format!("MPC-TLS request failed with status {}", response.status()).into());
    }

    // Create proof for the Verifier.
    let mut prover = prover_task.await??;

    let transcript = prover.transcript().clone();
    let mut prove_config_builder = ProveConfig::builder(&transcript);

    // Reveal the DNS name.
    prove_config_builder.server_identity();

    let sent: &[u8] = transcript.sent();
    let received: &[u8] = transcript.received();
    let sent_len = sent.len();
    let recv_len = received.len();
    tracing::info!("Sent length: {}, Received length: {}", sent_len, recv_len);

    // Reveal the entire HTTP request except for the authorization bearer token
    reveal_request(sent, &mut prove_config_builder)?;

    // Create hash commitment for the date of birth field from the response
    let mut transcript_commitment_builder = TranscriptCommitConfig::builder(&transcript);
    transcript_commitment_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    reveal_received(
        received,
        &mut prove_config_builder,
        &mut transcript_commitment_builder,
    )?;

    let transcripts_commitment_config = transcript_commitment_builder.build()?;
    prove_config_builder.transcript_commit(transcripts_commitment_config);

    let prove_config = prove_config_builder.build()?;

    // MPC-TLS prove
    let prover_output = prover.prove(&prove_config).await?;
    prover.close().await?;

    // Prove birthdate is more than 18 years ago.
    let received_commitments = received_commitments(&prover_output.transcript_commitments);
    let received_commitment = received_commitments
        .first()
        .ok_or("No received commitments found")?; // committed hash (of date of birth string)
    let received_secrets = received_secrets(&prover_output.transcript_secrets);
    let received_secret = received_secrets
        .first()
        .ok_or("No received secrets found")?; // hash blinder
    let proof_input = prepare_zk_proof_input(received, received_commitment, received_secret)?;
    let proof_bundle = generate_zk_proof(&proof_input)?;

    // Sent zk proof bundle to verifier
    let serialized_proof = bincode::serialize(&proof_bundle)?;
    verifier_extra_socket.write_all(&serialized_proof).await?;
    verifier_extra_socket.shutdown().await?;

    Ok(())
}

// Reveal everything from the request, except for the authorization token.
fn reveal_request(
    request: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reqs = Requests::new_from_slice(request).collect::<Result<Vec<_>, _>>()?;

    let req = reqs.first().ok_or("No requests found")?;

    if req.request.method.as_str() != "GET" {
        return Err(format!("Expected GET method, found {}", req.request.method.as_str()).into());
    }

    let authorization_header = req
        .headers_with_name(header::AUTHORIZATION.as_str())
        .next()
        .ok_or("Authorization header not found")?;

    let start_pos = authorization_header
        .span()
        .indices()
        .min()
        .ok_or("Could not find authorization header start position")?
        + header::AUTHORIZATION.as_str().len()
        + 2;
    let end_pos =
        start_pos + authorization_header.span().len() - header::AUTHORIZATION.as_str().len() - 2;

    builder.reveal_sent(&(0..start_pos))?;
    builder.reveal_sent(&(end_pos..request.len()))?;

    Ok(())
}

fn reveal_received(
    received: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
    transcript_commitment_builder: &mut TranscriptCommitConfigBuilder,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = Responses::new_from_slice(received).collect::<Result<Vec<_>, _>>()?;

    let response = resp.first().ok_or("No responses found")?;
    let body = response.body.as_ref().ok_or("Response body not found")?;

    let BodyContent::Json(json) = &body.content else {
        return Err("Expected JSON body content".into());
    };

    // reveal tax year
    let tax_year = json
        .get("tax_year")
        .ok_or("tax_year field not found in JSON")?;
    let start_pos = tax_year
        .span()
        .indices()
        .min()
        .ok_or("Could not find tax_year start position")?
        - 11;
    let end_pos = tax_year
        .span()
        .indices()
        .max()
        .ok_or("Could not find tax_year end position")?
        + 1;
    builder.reveal_recv(&(start_pos..end_pos))?;

    // commit to hash of date of birth
    let dob = json
        .get("taxpayer.date_of_birth")
        .ok_or("taxpayer.date_of_birth field not found in JSON")?;

    transcript_commitment_builder.commit_recv(dob.span())?;

    Ok(())
}

// extract secret from prover output
fn received_secrets(transcript_secrets: &[TranscriptSecret]) -> Vec<&PlaintextHashSecret> {
    transcript_secrets
        .iter()
        .filter_map(|secret| match secret {
            TranscriptSecret::Hash(hash) if hash.direction == Direction::Received => Some(hash),
            _ => None,
        })
        .collect()
}

#[derive(Debug)]
pub struct ZKProofInput {
    dob: Vec<u8>,
    proof_date: NaiveDate,
    blinder: Vec<u8>,
    committed_hash: Vec<u8>,
}

// Verify that the blinded, committed hash is correct
fn prepare_zk_proof_input(
    received: &[u8],
    received_commitment: &PlaintextHash,
    received_secret: &PlaintextHashSecret,
) -> Result<ZKProofInput, Box<dyn std::error::Error>> {
    assert_eq!(received_commitment.direction, Direction::Received);
    assert_eq!(received_commitment.hash.alg, HashAlgId::SHA256);

    let hash = &received_commitment.hash;

    let dob_start = received_commitment
        .idx
        .min()
        .ok_or("No start index for DOB")?;
    let dob_end = received_commitment
        .idx
        .end()
        .ok_or("No end index for DOB")?;
    let dob = received[dob_start..dob_end].to_vec();
    let blinder = received_secret.blinder.as_bytes().to_vec();
    let committed_hash = hash.value.as_bytes().to_vec();
    let proof_date = Local::now().date_naive();

    assert_eq!(received_secret.direction, Direction::Received);
    assert_eq!(received_secret.alg, HashAlgId::SHA256);

    let mut hasher = Sha256::new();
    hasher.update(&dob);
    hasher.update(&blinder);
    let computed_hash = hasher.finalize();

    if committed_hash != computed_hash.as_slice() {
        return Err("Computed hash does not match committed hash".into());
    }

    Ok(ZKProofInput {
        dob,
        proof_date,
        committed_hash,
        blinder,
    })
}

fn generate_zk_proof(
    proof_input: &ZKProofInput,
) -> Result<ZKProofBundle, Box<dyn std::error::Error>> {
    tracing::info!("🔒 Generating ZK proof with Noir...");

    const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");

    // 1. Load bytecode from program.json
    let json: Value = serde_json::from_str(PROGRAM_JSON)?;
    let bytecode = json["bytecode"]
        .as_str()
        .ok_or("bytecode field not found in program.json")?;

    let mut inputs: Vec<String> = vec![];
    inputs.push(proof_input.proof_date.day().to_string());
    inputs.push(proof_input.proof_date.month().to_string());
    inputs.push(proof_input.proof_date.year().to_string());
    inputs.extend(proof_input.committed_hash.iter().map(|b| b.to_string()));
    inputs.extend(proof_input.dob.iter().map(|b| b.to_string()));
    inputs.extend(proof_input.blinder.iter().map(|b| b.to_string()));

    let proof_date = proof_input.proof_date.to_string();
    tracing::info!(
        "Public inputs : Proof date ({}) and committed hash ({})",
        proof_date,
        hex::encode(&proof_input.committed_hash)
    );
    tracing::info!(
        "Private inputs: Blinder ({}) and Date of Birth ({})",
        hex::encode(&proof_input.blinder),
        String::from_utf8_lossy(&proof_input.dob)
    );

    tracing::debug!("Witness inputs {:?}", inputs);

    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let witness = from_vec_str_to_witness_map(input_refs)?;

    // Setup SRS
    setup_srs_from_bytecode(bytecode, None, false)?;

    // Verification key
    let vk = get_ultra_honk_verification_key(bytecode, false)?;

    // Generate proof
    let proof = prove_ultra_honk(bytecode, witness.clone(), vk.clone(), false)?;
    tracing::info!("✅ Proof generated ({} bytes)", proof.len());

    let proof_bundle = ZKProofBundle { vk, proof };
    Ok(proof_bundle)
}
