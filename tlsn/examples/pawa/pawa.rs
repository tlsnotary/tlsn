use actix_web::{post, web, App, HttpServer, HttpResponse};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use std::io::Write;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, error, info, warn};
use tracing_subscriber;

#[derive(Deserialize, Debug)]
struct PayoutCallback {
    amount: String,
    correspondent: String,
    country: String,
    created: String,
    currency: String,
    customer_timestamp: String,
    failure_reason: Option<FailureReason>,
    payout_id: String,
    recipient: Recipient,
    statement_description: String,
    status: String,
}

#[derive(Deserialize, Debug)]
struct FailureReason {
    failure_code: String,
    failure_message: String,
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
    info!("{}", log_message);

    // Write to a log file for further inspection
    if let Err(e) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("callback.log")
        .and_then(|mut file| writeln!(file, "{}", log_message))
    {
        error!("Failed to write to log file: {:?}", e);
    }

    match payout.status.as_str() {
        "FAILED" => {
            if let Some(failure_reason) = &payout.failure_reason {
                warn!("Payout failed: {} - {}", failure_reason.failure_code, failure_reason.failure_message);
            }
        }
        "ACCEPTED" | "COMPLETED" => {
            info!("Payout accepted: {}", payout.payout_id);
            if let Err(e) = notarize_callback(&payout).await {
                error!("Error notarizing callback: {:?}", e);
            }
        }
        "ENQUEUED" => {
            info!("Payout enqueued: {}", payout.payout_id);
        }
        _ => {
            warn!("Unknown status: {}", payout.status);
        }
    }

    HttpResponse::Ok().finish()
}

async fn notarize_callback(payout: &PayoutCallback) -> Result<(), Box<dyn std::error::Error>> {
    // Setting of the notary server
    const NOTARY_HOST: &str = "https://notary.pse.dev/v0.1.0-alpha.6";
    const NOTARY_PORT: u16 = 443;

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        .build()?;

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder().build()?;
    let Accepted { io: notary_connection, id: session_id, .. } = notary_client
        .request_notarization(notarization_request)
        .await?;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns("api.sandbox.pawapay.cloud")
        .build()?;

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_connection.compat())
        .await?;

    let client_socket = tokio::net::TcpStream::connect(("api.sandbox.pawapay.cloud", 443)).await?;
    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Grab a control handle to the Prover
    let prover_ctrl = prover_fut.control();
    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection).await?;
    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the callback data
    let request = Request::builder()
        .uri(format!("https://api.sandbox.pawapay.cloud/payouts/{}", payout.payout_id))
        .header("Host", "api.sandbox.pawapay.cloud")
        .header("Accept", "*/*")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())?;

    debug!("Sending request");

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await?;
    let response = request_sender.send_request(request).await?;

    // debug!("Sent request");
    // if response.status() != StatusCode::OK {
    //     return Err(Box::new(ClientError {
    //         kind: ClientErrorKind::Http,
    //         source: Some(hyper::Error::from(hyper::http::Error::from(
    //             format!("Unexpected status code: {}", response.status()),
    //         ))),
    //     }));
    // }
    // debug!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await?.to_bytes();
    let parsed = serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload))?;
    debug!("{}", serde_json::to_string_pretty(&parsed)?);

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await??;

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.to_http()?.start_notarize();

    // Commit to the transcript with the default committer, which will commit using BLAKE3.
    prover.commit()?;

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await?;
    debug!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("callback_notarized.json").await?;
    file.write_all(serde_json::to_string_pretty(notarized_session.session())?.as_bytes()).await?;

    let session_proof = notarized_session.session_proof();
    let mut proof_builder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request = &notarized_session.transcript().requests[0];
    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)?;
    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)?;
    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)?;
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)?;
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];
    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)?;

    // Build the proof
    let substrings_proof = proof_builder.build()?;
    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("callback_proof.json").await?;
    file.write_all(serde_json::to_string_pretty(&proof)?.as_bytes()).await?;

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("debug,yamux=info")
        .init();

    HttpServer::new(|| {
        App::new()
            .service(callback)
    })
    .bind("127.0.0.1:8088")?
    .run()
    .await
}
