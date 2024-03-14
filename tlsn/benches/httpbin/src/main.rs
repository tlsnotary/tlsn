use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::time::Instant;
use tlsn_core::Direction;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn_prover::tls::{state, Prover, ProverConfig};

const SERVER_DOMAIN: &str = "httpbin.org";
const NOTARY_HOST: &str = "notary.pse.dev";
const NOTARY_PORT: u16 = 443;

// These MUST be identical to what the nightly deployment of the notary server has configured.
const NOTARY_MAX_SENT: usize = 1 << 12;
const NOTARY_MAX_RECV: usize = 1 << 14;

mod arg_parse;
mod notarize;

use arg_parse::{arg_parse, BenchOptions};
use notarize::request_notarization;

#[tokio::main]
async fn main() {
    let mut args = arg_parse();

    while let Some(bench_options) = args.split_off() {
        println!(
            "\nStarting timer for notarization with\n\tdeferred decryption={:?}\n\tsize={:?} bytes\n\tverify={:?}\n",
            bench_options.defer_decryption, bench_options.size, bench_options.verify
        );

        let start_time = Instant::now();
        prove(bench_options, start_time).await;

        let duration = Instant::now().duration_since(start_time).as_secs();
        println!("\nFinished in {duration} seconds\n");
    }
}

async fn prove(options: BenchOptions, time: Instant) {
    let (notary_tls_socket, session_id) = request_notarization(
        NOTARY_HOST,
        NOTARY_PORT,
        Some(NOTARY_MAX_SENT),
        Some(NOTARY_MAX_RECV),
        time,
    )
    .await;

    // Basic default prover config using the session_id returned from /session endpoint just now.
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    print_with_time("Setting up MPC backend", time);

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    print_with_time("Connecting to server", time);
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection.
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let prover_ctrl = prover_fut.control();
    let prover_task = tokio::spawn(prover_fut);

    // Depending on command line flag, use deferred decryption.
    if options.defer_decryption {
        prover_ctrl.defer_decryption().await.unwrap();
    }

    // Attach the hyper HTTP client to the TLS connection.
    print_with_time("Doing handshake", time);
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request
    let request = Request::builder()
        .uri(format!("https://{SERVER_DOMAIN}/bytes/{}", options.size))
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        )
        .body(Empty::<Bytes>::new())
        .unwrap();

    print_with_time("Starting notarization", time);
    let response = request_sender.send_request(request).await.unwrap();

    assert!(
        response.status() == StatusCode::OK,
        "Response was not OK: {}",
        response.status()
    );
    let payload = response.into_body().collect().await.unwrap().to_bytes();

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();
    print_with_time(format!("Got response of {} bytes.", payload.len()), time);

    // Either notarize or verify
    if options.verify {
        verify(prover).await;
    } else {
        notarize(prover).await;
    }
    print_with_time("Finalized", time);
}

async fn notarize(prover: Prover<state::Closed>) {
    // Start commitment phase
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

async fn verify(prover: Prover<state::Closed>) {
    // Start verification phase
    let mut prover = prover.start_prove();

    let recv_len = prover.recv_transcript().data().len();
    let sent_len = prover.sent_transcript().data().len();

    prover.reveal(0..sent_len, Direction::Sent).unwrap();
    prover.reveal(0..recv_len, Direction::Received).unwrap();

    prover.prove().await.unwrap();

    // Finalize
    prover.finalize().await.unwrap();
}

fn print_with_time(input: impl ToString, time: Instant) {
    let input = input.to_string();
    let duration = Instant::now().duration_since(time).as_millis();
    println!("\t{duration}ms\t{input}");
}
