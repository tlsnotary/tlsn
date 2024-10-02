// Runs a simple Prover which connects to the Notary and notarizes a
// request/response from example.com. The Prover then generates an attestation and
// writes it to disk.

use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{
    presentation::Presentation,
    request::RequestConfig,
    transcript::{Direction, TranscriptCommitConfig},
    CryptoProvider,
};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn_examples::run_notary;
use tlsn_prover::{state::Notarize, Prover, ProverConfig};
use utils::range::RangeSet;

// Setting of the application server
const SERVER_DOMAIN: &str = "example.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

use std::str;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 16);

    // Start a local simple notary service
    tokio::spawn(run_notary(notary_socket.compat()));

    // Prover configuration.
    let config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // Configure the limit of the data sent and received.
                .max_sent_data(1024)
                .max_recv_data(4096)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    let prover = Prover::new(config)
        .setup(prover_socket.compat())
        .await
        .unwrap();

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the Notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the MPC TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let request = Request::builder()
        .uri("/")
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())
        .unwrap();

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the Server and get a response via the MPC TLS connection
    let response = request_sender.send_request(request).await.unwrap();

    println!("Got a response from the server");

    assert!(response.status() == StatusCode::OK);

    // The Prover task should be done now, so we can grab the Prover.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let prover = prover.start_notarize();

    // Build presentation (with or without redaction)
    let redact = false;
    let presentation = build_presentation(redact, prover).await;

    // Write the presentation to a file
    let mut file = tokio::fs::File::create("simple_attestation.json")
        .await
        .unwrap();
    file.write_all(
        serde_json::to_string_pretty(&presentation)
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    println!("Notarization completed successfully!");
    println!("The attestation has been written to `simple_attestation.json`");
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (RangeSet<usize>, RangeSet<usize>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (
        RangeSet::from(public_ranges),
        RangeSet::from(private_ranges),
    )
}

async fn build_presentation(redact: bool, mut prover: Prover<Notarize>) -> Presentation {
    let sent_transcript = prover.transcript().sent();
    let recv_transcript = prover.transcript().received();

    let (sent_public_ranges, recv_public_ranges) = if !redact {
        (
            // Commit to everything
            RangeSet::from(0..sent_transcript.len()),
            RangeSet::from(0..recv_transcript.len()),
        )
    } else {
        (
            // Identify the ranges in the outbound data which contain data which we want to
            // disclose
            find_ranges(
                sent_transcript,
                &[
                    // Redact the value of the "User-Agent" header. It will NOT be disclosed.
                    USER_AGENT.as_bytes(),
                ],
            )
            .0,
            // Identify the ranges in the inbound data which contain data which we want to disclose
            find_ranges(
                recv_transcript,
                &[
                    // Redact the value of the title. It will NOT be disclosed.
                    "Example Domain".as_bytes(),
                ],
            )
            .0,
        )
    };

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    let _ = builder.commit_sent(&sent_public_ranges).unwrap();
    let _ = builder.commit_recv(&recv_public_ranges).unwrap();

    let config = builder.build().unwrap();

    prover.transcript_commit(config);

    // Finalize, returning the notarized session
    let request_config = RequestConfig::default();
    let (attestation, secrets) = prover.finalize(&request_config).await.unwrap();

    println!("notarization complete");

    // Create a proof for all committed data in this session
    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);

    attestation.presentation_builder(&provider);

    builder.identity_proof(secrets.identity_proof());

    let mut transcript_proof_builder = secrets.transcript_proof_builder();

    // Reveal all the public ranges
    let _ = transcript_proof_builder.reveal(&sent_public_ranges, Direction::Sent);
    let _ = transcript_proof_builder.reveal(&recv_public_ranges, Direction::Received);

    builder.transcript_proof(transcript_proof_builder.build().unwrap());

    builder.build().map(Presentation::from).unwrap()
}
