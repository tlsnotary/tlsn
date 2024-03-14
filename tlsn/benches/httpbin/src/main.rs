use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::time::Instant;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info};

use tlsn_prover::tls::{Prover, ProverConfig};

const SERVER_DOMAIN: &str = "httpbin.org";
const NOTARY_HOST: &str = "notary.pse.dev";
const NOTARY_PORT: u16 = 433;

// Configuration of notarization
const NOTARY_MAX_SENT: usize = 1 << 12;
const NOTARY_MAX_RECV: usize = 1 << 14;

mod env_parse;
mod notarize;

use env_parse::{parse_env, BenchOptions};
use notarize::request_notarization;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let mut env = parse_env();
    let mut durations = vec![];

    while let Some(bench_options) = env.split_off() {
        info!(
            "Starting notarization with deferred decryption={:?} and size of {:?} bytes.",
            bench_options.defer_decryption, bench_options.size
        );

        let start_time = Instant::now();
        prove(bench_options).await;
        let duration = Instant::now().duration_since(start_time).as_secs();

        info!("Finished in {duration} seconds.");
        durations.push(duration);
    }
}

async fn prove(options: BenchOptions) {
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
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    if options.defer_decryption {
        let prover_ctrl = prover_fut.control();
        prover_ctrl.defer_decryption().await.unwrap();
    }

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .uri(format!("https://{SERVER_DOMAIN}/bytes/{}", options.size))
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .unwrap();

    debug!("Sending request...");

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    debug!("Received {} bytes response", payload.len());

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization
    let mut prover = prover.start_notarize();

    let recv_len = prover.recv_transcript().data().len();
    let sent_len = prover.sent_transcript().data().len();

    let builder = prover.commitment_builder();

    // Commit to everything
    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    // Finalize
    prover.finalize().await.unwrap();
}
