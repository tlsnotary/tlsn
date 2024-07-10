use dotenv::dotenv;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use std::{
    env,
    io::{self, Write},
};
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_examples::PayoutResponse;
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    print!("Enter payout id: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut payout_id = String::new();
    io::stdin()
        .read_line(&mut payout_id)
        .expect("Failed to read line");

    let payout_id = payout_id.trim();

    println!("Payout ID: {}", payout_id);
    let server_domain = "api.sandbox.pawapay.cloud";

    tracing_subscriber::fmt()
        .with_env_filter("debug,yamux=info")
        .init();

    dotenv().ok();

    let jwt = env::var("JWT").expect("JWT must be set");

    const NOTARY_HOST: &str = "notary.pse.dev";
    const NOTARY_PORT: u16 = 443;

    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        .enable_tls(true)
        .build()
        .unwrap();
    info!("Created Notary Client");

    let notarization_request = NotarizationRequest::builder().build().unwrap();

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(server_domain)
        .build()
        .unwrap();

    let prover = Prover::new(config)
        .setup(notary_connection.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((server_domain, 443))
        .await
        .unwrap();

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let tls_connection = TokioIo::new(tls_connection.compat());

    let prover_ctrl = prover_fut.control();

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();

    tokio::spawn(connection);

    // Create the request
    // let request = Request::builder()
    //     .method("GET")
    //     .uri(format!(
    //         "https://{}/payouts/{}",
    //         server_domain, payout_id
    //     ))
    //     .header("Authorization", format!("Bearer {jwt}"))
    //     .header("Content-Type", "application/json")
    //     .body(Empty::<Bytes>::new()).unwrap();

    // let request = Request::get(format!("https://{}/payouts/{}", server_domain, payout_id))
    //     .header(
    //         hyper::header::AUTHORIZATION,
    //         format!("Bearer {}", jwt.to_string()),
    //     )
    //     .header("Content-Type", "application/json")
    //     .header(hyper::header::HOST, server_domain.to_string())
    //     .body(Empty::<Bytes>::new())
    //     .unwrap();

    let url = "https://api.sandbox.pawapay.cloud/payouts/55b3c3e9-7919-48cc-96f4-a80c988b36c2"
        .parse::<hyper::Uri>().unwrap();
    let jwt = "eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJqdGkiOiJlNWZhYzYyMS0wNWM1LTQ5ZTMtYjg2OS1kODAyMWU5YzI3NmEiLCJzdWIiOiIxOTg5IiwiaWF0IjoxNzE5NDc5OTY2LCJleHAiOjIwMzUwMTI3NjYsInBtIjoiREFGLFBBRiIsInR0IjoiQUFUIn0.1SjH1y-FCIfKYQncc_pNaTZ232ImZH7vTpg3Ab9wlPM";
    // Create an HTTP request with an empty body and the required headers
    let request = Request::get(url.clone())
        .header("Authorization", format!("Bearer {}", jwt))
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::HOST, "api.sandbox.pawapay.cloud")
        .header("Connection", "close")
        .header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .header("Accept", "*/*")
        .body(Empty::<Bytes>::new()).unwrap();

    debug!("Sending request: {:?}", request);

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await.unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    debug!("Payload: {:?}", payload);
    let response_body = String::from_utf8_lossy(&payload);
    println!("Response: {}", response_body);

    // Deserialize the response
    let payout_responses: Vec<PayoutResponse> = serde_json::from_str(&response_body).unwrap();

    // Assert the status is COMPLETED
    for payout_response in payout_responses {
        assert_eq!(
            payout_response.status, "COMPLETED",
            "Payout status is not COMPLETED"
        );
    }

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
    let mut file = tokio::fs::File::create("payout_status.json").await.unwrap();
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
    let mut file = tokio::fs::File::create("payout_status_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    Ok(())
}
