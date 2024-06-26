use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::convert::Infallible;
use std::env;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_examples::request_notarization;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use tlsn_prover::tls::{Prover, ProverConfig};
use chrono::Utc;

#[derive(Deserialize)]
struct PayoutStatus {
    status: String,
    payout_id: String,
}

async fn callback_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::POST && req.uri().path() == "/callback" {
        let whole_body = hyper::body::to_bytes(req.into_body()).await.unwrap();
        let payout_status: PayoutStatus = serde_json::from_slice(&whole_body).unwrap();
        debug!("Received callback: {:?}", payout_status);
        // Notarize the callback response here
        Ok(Response::new(Body::from("Callback received")))
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap())
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    // Load secret variables from environment for pawaPay server connection
    dotenv::dotenv().ok();
    let api_token = env::var("API_TOKEN").unwrap();
    let payout_id = env::var("PAYOUT_ID").unwrap();

    let (notary_tls_socket, session_id) = request_notarization(
        "127.0.0.1",
        7047,
        Some(1 << 12),
        Some(1 << 14),
    )
    .await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns("https://api.sandbox.pawapay.cloud/")
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect(("3.64.89.224", 443))
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

    let current_timestamp = Utc::now().to_rfc3339();

    // Build the HTTP request to send the payout
    let request_body = serde_json::json!({
        "payoutId": payout_id,
        "amount": "19",
        "currency": "GHS",
        "country": "GHA",
        "correspondent": "MTN_MOMO_GHA",
        "recipient": {
            "type": "MSISDN",
            "address": {
                "value": "233593456119"
            }
        },
        "customerTimestamp": current_timestamp,
        "statementDescription": "Note of 4 to 22 chars",
        "metadata": [
            {
                "fieldName": "orderId",
                "fieldValue": "ORD-123456789"
            },
            {
                "fieldName": "customerId",
                "fieldValue": "customer@email.com",
                "isPII": true
            }
        ]
    });

    let request = Request::builder()
        .uri("https://api.sandbox.pawapay.cloud/payouts")
        .header("Host", "api.sandbox.pawapay.cloud")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "gzip, x-gzip, deflate")
        .header("Content-Type", "application/json; charset=UTF-8")
        .header("Authorization", format!("Bearer {}", api_token))
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
        .body(Body::from(request_body.to_string()))
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
    let payload = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let parsed = serde_json::from_slice::<serde_json::Value>(&payload).unwrap();
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
    let mut file = tokio::fs::File::create("pawapay_payout.json").await.unwrap();
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
    let mut file = tokio::fs::File::create("pawapay_payout_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    // Start the hyper server to handle callbacks
    let make_svc = make_service_fn(|_conn| {
        async { Ok::<_, Infallible>(service_fn(callback_handler)) }
    });

    let addr = ([127, 0, 0, 1], 8080).into();

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}