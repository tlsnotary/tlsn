/// Runs a simple Prover which connects to the Notary and notarizes a request/response from
/// example.com. The Prover then generates a proof and writes it to disk.
///
/// The example uses the notary server implemented in ./simple_notary.rs
use futures::AsyncWriteExt;
use hyper::{Body, Request, StatusCode};
use std::ops::Range;
use tlsn_core::proof::TlsProof;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn_prover::tls::{Prover, ProverConfig};

// Setting of the application server
const SERVER_DOMAIN: &str = "example.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

// Setting of the notary server — make sure these are the same with those in ./simple_notary.rs
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 8080;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // A Prover configuration
    let config = ProverConfig::builder()
        .id("example")
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Connect to the Notary
    let notary_socket = tokio::net::TcpStream::connect((NOTARY_HOST, NOTARY_PORT))
        .await
        .unwrap();
    println!("Connected to the Notary");

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    let prover = Prover::new(config)
        .setup(notary_socket.compat())
        .await
        .unwrap();

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the MPC TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::handshake(mpc_tls_connection.compat())
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

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
        .body(Body::empty())
        .unwrap();

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the Server and get a response via the MPC TLS connection
    let response = request_sender.send_request(request).await.unwrap();

    println!("Got a response from the server");

    assert!(response.status() == StatusCode::OK);

    // Close the connection to the server
    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();
    client_socket.close().await.unwrap();

    // The Prover task should be done now, so we can grab the Prover.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Identify the ranges in the outbound data which contain data which we want to disclose
    let (sent_public_ranges, _) = find_ranges(
        prover.sent_transcript().data(),
        &[
            // Redact the value of the "User-Agent" header. It will NOT be disclosed.
            USER_AGENT.as_bytes(),
        ],
    );

    // Identify the ranges in the inbound data which contain data which we want to disclose
    let (recv_public_ranges, _) = find_ranges(
        prover.recv_transcript().data(),
        &[
            // Redact the value of the title. It will NOT be disclosed.
            "Example Domain".as_bytes(),
        ],
    );

    let builder = prover.commitment_builder();

    // Commit to each range of the public outbound data which we want to disclose
    let sent_commitments: Vec<_> = sent_public_ranges
        .iter()
        .map(|r| builder.commit_sent(r.clone()).unwrap())
        .collect();
    // Commit to each range of the public inbound data which we want to disclose
    let recv_commitments: Vec<_> = recv_public_ranges
        .iter()
        .map(|r| builder.commit_recv(r.clone()).unwrap())
        .collect();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    for commitment_id in sent_commitments {
        proof_builder.reveal(commitment_id).unwrap();
    }
    for commitment_id in recv_commitments {
        proof_builder.reveal(commitment_id).unwrap();
    }

    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    };

    // Write the proof to a file
    let mut file = tokio::fs::File::create("proof.json").await.unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    println!("Notarization completed successfully!");
    println!("The proof has been written to proof.json");
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
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

    (public_ranges, private_ranges)
}
