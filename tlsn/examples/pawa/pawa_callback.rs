use actix_web::{post, web, App, HttpResponse, HttpServer};
use dotenv::dotenv;
use hyper::{body::Body, Request};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use serde::{Deserialize, Serialize};
use std::{env, io::Write, sync::Arc};
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::{io::AsyncWriteExt as _, sync::Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use tlsn_examples::{PayoutRequest, PayoutCallback, Recipient, Address};

#[post("/callback")]
async fn callback(
    payout: web::Json<PayoutCallback>,
    tx: web::Data<Arc<Mutex<Option<tokio::sync::oneshot::Sender<PayoutCallback>>>>>,
) -> HttpResponse {
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
            if let Some(failure_reason) = &payout.failureReason {
                warn!(
                    "Payout failed: {} - {}",
                    failure_reason.failureCode, failure_reason.failureMessage
                );
            }
        }
        "ACCEPTED" | "COMPLETED" => {
            info!("Payout accepted: {}", payout.payoutId);
        }
        "ENQUEUED" => {
            info!("Payout enqueued: {}", payout.payoutId);
        }
        _ => {
            warn!("Unknown status: {}", payout.status);
        }
    }

    // Send the callback response through the oneshot channel
    if let Some(tx) = tx.lock().await.take() {
        let _ = tx.send(payout.into_inner());
    }

    HttpResponse::Ok().finish()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let jwt = env::var("JWT").expect("JWT must be set");

    tracing_subscriber::fmt()
        .with_env_filter("debug,yamux=info")
        .init();

    // Setting of the notary server
    const NOTARY_HOST: &str = "notary.pse.dev";
    const NOTARY_PORT: u16 = 443;

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        .enable_tls(true)
        .build()
        .unwrap();
    info!("Created Notary client");

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder().build().unwrap();
    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns("api.sandbox.pawapay.cloud")
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_connection.compat())
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

    // Create a oneshot channel to signal when the callback is received
    let (tx, rx) = tokio::sync::oneshot::channel::<PayoutCallback>();
    let tx = Arc::new(Mutex::new(Some(tx)));

    // Start the server to listen for the callback
    let server = HttpServer::new(move || {
        App::new()
            .service(callback)
            .app_data(web::Data::new(tx.clone()))
    })
    .bind("127.0.0.1:8088")?
    .run();

    // here we manually send the request
    debug!("Please send the payout now");

    // Send payout request
    let payout_request = PayoutRequest {
        payoutId: Uuid::new_v4().to_string(),
        amount: "19".to_string(),
        currency: "GHS".to_string(),
        country: "GHA".to_string(),
        correspondent: "MTN_MOMO_GHA".to_string(),
        recipient: Recipient {
            recipient_type: "MSISDN".to_string(),
            address: Address {
                value: "233593456789".to_string(),
            },
        },
        customerTimestamp: "2024-06-27T01:32:28Z".to_string(),
        statementDescription: "For the culture".to_string(),
    };

    let request = Request::builder()
        .uri("https://api.sandbox.pawapay.cloud/payouts")
        .header("Host", "api.sandbox.pawapay.cloud")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        )
        .header("Authorization", format!("Bearer {}", jwt))
        .header("Content-Type", "application/json")
        .body(&mut Body::from(serde_json::to_vec(&payout_request).unwrap()))
        .unwrap();

    debug!("Sending request");

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await.unwrap();

    request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    // Wait for the callback to be received
    let payout_callback = rx.await.expect("Failed to receive callback");

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
    let mut file = tokio::fs::File::create("callback_notarized.json")
        .await
        .unwrap();

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

    // Include the callback response in the proof
    let callback_response = serde_json::to_string(&payout_callback).unwrap();
    proof_builder
        .reveal_sent(&callback_response.into_bytes(), CommitmentKind::Blake3)
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

    // Stop the server gracefully
    server.stop(true).await;

    Ok(())
}
