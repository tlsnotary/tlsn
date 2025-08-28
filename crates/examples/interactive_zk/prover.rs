use std::net::SocketAddr;

use super::types::Message;

use chrono::Datelike;
use chrono::Local;
use http_body_util::Empty;
use hyper::{body::Bytes, header, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use k256::sha2::{Digest, Sha256};
use noir::barretenberg::srs::setup_srs_from_bytecode;
use noir::{
    barretenberg::{
        prove::prove_ultra_honk,
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
    prover::{
        ProveConfig, ProveConfigBuilder, Prover, ProverConfig, ProverOutput,
        TlsConfig,
    },
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        Direction, TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret,
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
) {
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();

    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    let mut tls_config_builder = TlsConfig::builder();
    tls_config_builder.root_store(RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    });
    let tls_config = tls_config_builder.build().unwrap();

    // Set up protocol configuration for prover.
    let mut prover_config_builder = ProverConfig::builder();
    prover_config_builder
        .server_name(ServerName::Dns(server_domain.try_into().unwrap()))
        .tls_config(tls_config)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()
                .unwrap(),
        );

    let prover_config = prover_config_builder.build().unwrap();

    // Create prover and connect to verifier.
    //
    // Perform the setup phase with the verifier.
    let prover = Prover::new(prover_config)
        .setup(verifier_socket.compat())
        .await
        .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = tokio::net::TcpStream::connect(server_addr).await.unwrap();

    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header(header::AUTHORIZATION, "Bearer random_auth_token")
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    // Create proof for the Verifier.
    let mut prover = prover_task.await.unwrap().unwrap();

    let transcript = prover.transcript().clone();
    let mut builder = ProveConfig::builder(&transcript);

    // Reveal the DNS name.
    builder.server_identity();

    let sent: &[u8] = transcript.sent();
    let received: &[u8] = transcript.received();
    let sent_len = sent.len();
    let recv_len = received.len();
    println!("Sent length: {}, Received length: {}", sent_len, recv_len);

    reveal_request(sent, &mut builder);

    let mut transcript_commitment_builder = TranscriptCommitConfig::builder(&transcript);
    transcript_commitment_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });

    reveal_received(received, &mut builder, &mut transcript_commitment_builder);

    let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();
    builder.transcript_commit(transcripts_commitment_config);

    let prove_config = builder.build().unwrap();
    let prover_output = prover.prove(&prove_config).await.unwrap();

    prover.close().await.unwrap();

    let received_commitment: &PlaintextHash = received_commitment(&prover_output);

    let received_secret = received_secret(&prover_output);

    let (dob, committed_hash, blinder) =
        debug_check(received, received_commitment, received_secret);

    // Prepare inputs for Noir circuit
    let (vk, proof, check_date) =
        generate_zk_proof_with_noir_rs(committed_hash, blinder, dob).unwrap();

    let msg = Message {
        vk,
        proof,
        check_date,
    };
    let encoded_msg = bincode::serialize(&msg).unwrap();

    // Sent a string through the socket
    verifier_extra_socket.write_all(&encoded_msg).await.unwrap();
    verifier_extra_socket.shutdown().await.unwrap();
}

// Reveal everything sent, except for the authorization token.
fn reveal_request(sent: &[u8], builder: &mut ProveConfigBuilder<'_>) {
    let reqs = Requests::new_from_slice(sent)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(reqs[0].request.method.as_str(), "GET");
    let authorization_header = reqs[0]
        .headers_with_name(header::AUTHORIZATION.as_str())
        .next()
        .unwrap();

    let start_pos = authorization_header.span().indices().min().unwrap()
        + header::AUTHORIZATION.as_str().len()
        + 2;
    let end_pos =
        start_pos + authorization_header.span().len() - header::AUTHORIZATION.as_str().len() - 2;
    builder.reveal_sent(&(0..start_pos)).unwrap();
    builder.reveal_sent(&(end_pos..sent.len())).unwrap();
}

fn reveal_received(
    received: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
    transcript_commitment_builder: &mut TranscriptCommitConfigBuilder,
) {
    let resp = Responses::new_from_slice(received)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let body = resp[0].body.as_ref().unwrap();

    if let BodyContent::Json(json) = &body.content {
        // reveal tax year
        let tax_year = json.get("tax_year").unwrap();
        let start_pos = tax_year.span().indices().min().unwrap() - 11;
        let end_pos = tax_year.span().indices().max().unwrap() + 1;
        builder.reveal_recv(&(start_pos..end_pos)).unwrap();

        // commit to hash of date of birth
        let dob = json.get("taxpayer.date_of_birth").unwrap();
        println!("DOB: {:?}", dob);

        transcript_commitment_builder
            .commit_recv(dob.span())
            .unwrap();
    }
}

fn received_commitment(prover_output: &ProverOutput) -> &PlaintextHash {
    prover_output
        .transcript_commitments
        .iter()
        .filter(|commitment| {
            if let TranscriptCommitment::Hash(hash) = commitment {
                hash.direction == Direction::Received
            } else {
                false
            }
        })
        .map(|commitment| {
            if let TranscriptCommitment::Hash(hash) = commitment {
                hash
            } else {
                unreachable!()
            }
        })
        .next()
        .expect("missing received hash commitment")
}

fn received_secret(prover_output: &ProverOutput) -> &PlaintextHashSecret {
    prover_output
        .transcript_secrets
        .iter()
        .filter(|secret| {
            if let TranscriptSecret::Hash(hash) = secret {
                hash.direction == Direction::Received
            } else {
                false
            }
        })
        .map(|secret| {
            if let TranscriptSecret::Hash(hash) = secret {
                hash
            } else {
                unreachable!()
            }
        })
        .next()
        .expect("missing received hash commitment")
}

// Verify that the blinded, commited hash is correct
fn debug_check<'a>(
    received: &'a [u8],
    received_commitment: &'a PlaintextHash,
    received_secret: &'a PlaintextHashSecret,
) -> (&'a [u8], &'a [u8], &'a [u8]) {
    assert!(received_commitment.direction == Direction::Received);
    assert!(received_commitment.hash.alg == HashAlgId::SHA256);
    let hash = &received_commitment.hash;
    println!(
        "Hash of received data: {}",
        hex::encode(hash.value.as_bytes())
    );

    let dob = &received[received_commitment.idx.start()..received_commitment.idx.end()];
    let blinder = received_secret.blinder.as_bytes();
    let committed_hash = received_commitment.hash.value.as_bytes();

    assert!(received_secret.direction == Direction::Received);
    // dbg!(&received_commitment.idx);
    assert!(received_secret.alg == HashAlgId::SHA256);
    println!(
        "Blinder of received data: {}",
        hex::encode(received_secret.blinder.as_bytes())
    );

    let mut hasher = Sha256::new();
    hasher.update(dob);
    hasher.update(blinder);
    let computed_hash = hasher.finalize();

    // // Compare with the committed hash

    if computed_hash.as_slice() == committed_hash {
        println!("✅ Hash verification successful!");
        println!("Computed: {}", hex::encode(computed_hash));
        println!("Committed: {}", hex::encode(committed_hash));
    } else {
        println!("❌ Hash verification failed!");
        println!("Computed: {}", hex::encode(computed_hash));
        println!("Committed: {}", hex::encode(committed_hash));
    }

    (dob, committed_hash, blinder)
}

fn generate_zk_proof_with_noir_rs(
    committed_hash: &[u8],
    blinder: &[u8],
    dob: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, String), Box<dyn std::error::Error>> {
    println!("Generating ZK proof with noir_rs...");

    const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");

    // 1. Load bytecode from program.json
    let json: Value = serde_json::from_str(PROGRAM_JSON).unwrap();
    let bytecode = json["bytecode"].as_str().unwrap();

    let check_date: chrono::NaiveDate = Local::now().date_naive();
    let check_year = check_date.year();
    let check_month = check_date.month();
    let check_day = check_date.day();

    let mut inputs: Vec<String> = vec![];
    inputs.push(check_day.to_string());
    inputs.push(check_month.to_string());
    inputs.push(check_year.to_string());
    inputs.extend(committed_hash.iter().map(|b| b.to_string()));
    inputs.extend(dob.iter().map(|b| b.to_string()));
    inputs.extend(blinder.iter().map(|b| b.to_string()));

    println!("🔢 Inputs: {:?}", inputs);

    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let witness = from_vec_str_to_witness_map(input_refs).unwrap();

    // 4. Setup SRS
    setup_srs_from_bytecode(bytecode, None, false).unwrap();

    // 5. Verification key
    let vk = get_ultra_honk_verification_key(bytecode, false).unwrap();

    // 6. Generate proof
    let proof = prove_ultra_honk(bytecode, witness.clone(), vk.clone(), false).unwrap();
    println!("✅ Proof generated ({} bytes)", proof.len());

    Ok((
        vk.clone(),
        proof.clone(),
        check_date.format("%Y-%m-%d").to_string(),
    ))
}
