use actix_web::{post, web, App, HttpServer, HttpResponse};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tlsn_examples::request_notarization;
use std::io::Write;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

#[derive(Deserialize, Debug)]
struct PayoutCallback {
    amount: String,
    correspondent: String,
    country: String,
    created: String,
    currency: String,
    customerTimestamp: String,
    failureReason: Option<FailureReason>,
    payoutId: String,
    recipient: Recipient,
    statementDescription: String,
    status: String,
}

#[derive(Deserialize, Debug)]
struct FailureReason {
    failureCode: String,
    failureMessage: String,
}

#[derive(Deserialize, Debug)]
struct Recipient {
    #[serde(rename = "type")]
    recipient_type: String,
    address: Address,
}

#[derive(Deserialize, Debug)]
struct Address {
    value: String,
}

#[post("/callback")]
async fn callback(payout: web::Json<PayoutCallback>) -> HttpResponse {
    let log_message = format!("Received callback: {:?}", payout);
    println!("{}", log_message);

    // Write to a log file for further inspection
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("callback.log")
        .unwrap();
    writeln!(file, "{}", log_message).unwrap();

    match payout.status.as_str() {
        "FAILED" => {
            if let Some(failure_reason) = &payout.failureReason {
                println!("Payout failed: {} - {}", failure_reason.failureCode, failure_reason.failureMessage);
            }
        }
        "ACCEPTED" | "COMPLETED" => {
            println!("Payout accepted: {}", payout.payoutId);
            if let Err(e) = notarize_callback(&payout).await {
                eprintln!("Error notarizing callback: {:?}", e);
            }
        }
        "ENQUEUED" => {
            println!("Payout enqueued: {}", payout.payoutId);
        }
        _ => {
            println!("Unknown status: {}", payout.status);
        }
    }

    HttpResponse::Ok().finish()
}


async fn notarize_callback(payout: &PayoutCallback) -> Result<(), Box<dyn std::error::Error>> {
    // tracing_subscriber::fmt::init();

    // Setting of the notary server
    const NOTARY_HOST: &str = "127.0.0.1";
    const NOTARY_PORT: u16 = 7047;

    // Configuration of notarization
    const NOTARY_MAX_SENT: usize = 1 << 12;
    const NOTARY_MAX_RECV: usize = 1 << 14;

    let (notary_tls_socket, session_id) = request_notarization(
        NOTARY_HOST,
        NOTARY_PORT,
        Some(NOTARY_MAX_SENT),
        Some(NOTARY_MAX_RECV),
    )
    .await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns("api.sandbox.pawapay.cloud")
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect(("api.sandbox.pawapay.cloud", 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Grab a control handle to the Prover
    let prover_ctrl = prover_fut.control();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the callback data
    let request = Request::builder()
        .uri(format!(
            "https://api.sandbox.pawapay.cloud/payouts/{}",
            payout.payoutId
        ))
        .header("Host", "api.sandbox.pawapay.cloud")
        .header("Accept", "*/*")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .unwrap();

    debug!("Sending request");

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await.unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.to_http().unwrap().start_notarize();

    // Commit to the transcript with the default committer, which will commit using BLAKE3.
    prover.commit().unwrap();

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("callback_notarized.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(notarized_session.session())
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();

    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("callback_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(callback)
    })
    .bind("127.0.0.1:8088")?
    .run()
    .await
}
