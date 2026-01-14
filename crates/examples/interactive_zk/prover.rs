use std::net::SocketAddr;

use crate::types::received_commitments;

use super::types::ZKProofBundle;

use anyhow::Result;
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
use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn::{
    config::{
        prove::{ProveConfig, ProveConfigBuilder},
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
    },
    connection::ServerName,
    hash::HashAlgId,
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        Direction, TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitmentKind,
        TranscriptSecret,
    },
    webpki::{CertificateDer, RootCertStore},
    Session,
};

use futures::io::AsyncWriteExt as _;
use tlsn_examples::{MAX_RECV_DATA, MAX_SENT_DATA};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

#[instrument(skip(verifier_socket))]
pub async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
) -> Result<()> {
    let uri = uri.parse::<Uri>()?;

    if uri.scheme().map(|s| s.as_str()) != Some("https") {
        return Err(anyhow::anyhow!("URI must use HTTPS scheme"));
    }

    let server_domain = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("URI must have authority"))?
        .host();

    // Create a session with the verifier.
    let session = Session::new(verifier_socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    // Create a new prover and perform necessary setup.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            TlsCommitConfig::builder()
                // Select the TLS commitment protocol.
                .protocol(
                    MpcTlsConfig::builder()
                        // We must configure the amount of data we expect to exchange beforehand,
                        // which will be preprocessed prior to the
                        // connection. Reducing these limits will improve
                        // performance.
                        .max_sent_data(MAX_SENT_DATA)
                        .max_recv_data(MAX_RECV_DATA)
                        .build()?,
                )
                .build()?,
        )
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect(server_addr).await?;

    // Bind the prover to the server connection.
    let (tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
                // Create a root certificate store with the server-fixture's self-signed
                // certificate. This is only required for offline testing with the
                // server-fixture.
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()?,
            client_socket.compat(),
        )
        .await?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

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
        return Err(anyhow::anyhow!(
            "MPC-TLS request failed with status {}",
            response.status()
        ));
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

    // Close the session and wait for the driver to complete, reclaiming the socket.
    handle.close();
    let mut socket = driver_task.await??;

    // Prove birthdate is more than 18 years ago.
    let received_commitments = received_commitments(&prover_output.transcript_commitments);
    let received_commitment = received_commitments
        .first()
        .ok_or_else(|| anyhow::anyhow!("No received commitments found"))?; // committed hash (of date of birth string)
    let received_secrets = received_secrets(&prover_output.transcript_secrets);
    let received_secret = received_secrets
        .first()
        .ok_or_else(|| anyhow::anyhow!("No received secrets found"))?; // hash blinder
    let proof_input = prepare_zk_proof_input(received, received_commitment, received_secret)?;
    let proof_bundle = generate_zk_proof(&proof_input)?;

    // Sent zk proof bundle to verifier
    let serialized_proof = bincode::serialize(&proof_bundle)?;
    socket.write_all(&serialized_proof).await?;
    socket.close().await?;

    Ok(())
}

// Reveal everything from the request, except for the authorization token.
fn reveal_request(request: &[u8], builder: &mut ProveConfigBuilder<'_>) -> Result<()> {
    let reqs = Requests::new_from_slice(request).collect::<Result<Vec<_>, _>>()?;

    let req = reqs
        .first()
        .ok_or_else(|| anyhow::anyhow!("No requests found"))?;

    if req.request.method.as_str() != "GET" {
        return Err(anyhow::anyhow!(
            "Expected GET method, found {}",
            req.request.method.as_str()
        ));
    }

    let authorization_header = req
        .headers_with_name(header::AUTHORIZATION.as_str())
        .next()
        .ok_or_else(|| anyhow::anyhow!("Authorization header not found"))?;

    let start_pos = authorization_header
        .span()
        .indices()
        .min()
        .ok_or_else(|| anyhow::anyhow!("Could not find authorization header start position"))?
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
) -> Result<()> {
    let resp = Responses::new_from_slice(received).collect::<Result<Vec<_>, _>>()?;

    let response = resp
        .first()
        .ok_or_else(|| anyhow::anyhow!("No responses found"))?;
    let body = response
        .body
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Response body not found"))?;

    let BodyContent::Json(json) = &body.content else {
        return Err(anyhow::anyhow!("Expected JSON body content"));
    };

    // reveal tax year
    let tax_year = json
        .get("tax_year")
        .ok_or_else(|| anyhow::anyhow!("tax_year field not found in JSON"))?;
    let start_pos = tax_year
        .span()
        .indices()
        .min()
        .ok_or_else(|| anyhow::anyhow!("Could not find tax_year start position"))?
        - 11;
    let end_pos = tax_year
        .span()
        .indices()
        .max()
        .ok_or_else(|| anyhow::anyhow!("Could not find tax_year end position"))?
        + 1;
    builder.reveal_recv(&(start_pos..end_pos))?;

    // commit to hash of date of birth
    let dob = json
        .get("taxpayer.date_of_birth")
        .ok_or_else(|| anyhow::anyhow!("taxpayer.date_of_birth field not found in JSON"))?;

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
) -> Result<ZKProofInput> {
    assert_eq!(received_commitment.direction, Direction::Received);
    assert_eq!(received_commitment.hash.alg, HashAlgId::SHA256);

    let hash = &received_commitment.hash;

    let dob_start = received_commitment
        .idx
        .min()
        .ok_or_else(|| anyhow::anyhow!("No start index for DOB"))?;
    let dob_end = received_commitment
        .idx
        .end()
        .ok_or_else(|| anyhow::anyhow!("No end index for DOB"))?;
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

    if committed_hash != computed_hash.as_ref() as &[u8] {
        return Err(anyhow::anyhow!(
            "Computed hash does not match committed hash"
        ));
    }

    Ok(ZKProofInput {
        dob,
        proof_date,
        committed_hash,
        blinder,
    })
}

fn generate_zk_proof(proof_input: &ZKProofInput) -> Result<ZKProofBundle> {
    tracing::info!("🔒 Generating ZK proof with Noir...");

    const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");

    // 1. Load bytecode from program.json
    let json: Value = serde_json::from_str(PROGRAM_JSON)?;
    let bytecode = json["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("bytecode field not found in program.json"))?;

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
    let witness = from_vec_str_to_witness_map(input_refs).map_err(|e| anyhow::anyhow!(e))?;

    // Setup SRS
    setup_srs_from_bytecode(bytecode, None, false).map_err(|e| anyhow::anyhow!(e))?;

    // Verification key
    let vk = get_ultra_honk_verification_key(bytecode, false).map_err(|e| anyhow::anyhow!(e))?;

    // Generate proof
    let proof = prove_ultra_honk(bytecode, witness.clone(), vk.clone(), false)
        .map_err(|e| anyhow::anyhow!(e))?;
    tracing::info!("✅ Proof generated ({} bytes)", proof.len());

    let proof_bundle = ZKProofBundle { vk, proof };
    Ok(proof_bundle)
}
