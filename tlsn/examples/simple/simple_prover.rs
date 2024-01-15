/// Runs a simple Prover which connects to the Notary and notarizes a request/response from
/// example.com. The Prover then generates a proof and writes it to disk.
///
/// The example uses the notary server implemented in ./simple_notary.rs
use futures::AsyncWriteExt;
use hyper::{Body, Method, Request, StatusCode};
use serde::Deserialize;
use std::ops::Range;
use tlsn_core::proof::TlsProof;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use std::env;
use std::str::FromStr;
use tlsn_prover::tls::{Prover, ProverConfig};

// Setting of the application server

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

// Setting of the notary server — make sure these are the same with those in ./simple_notary.rs
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 8080;
const SESSION_ID: &str = "example";

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // recieve logging here from the cli about which url to call
    let args: Vec<String> = env::args().collect();

    // validate that at least one more parameter is provided
    assert!(args.len() >= 2, "Please provide request structure");
    let request_json = args[1].clone();

    // read the proxy request
    let req_proxy: ProxyRequest = serde_json::from_str(&request_json[..]).unwrap();

    // A Prover configuration
    let config = ProverConfig::builder()
        .id(SESSION_ID)
        .server_dns(req_proxy.host.clone())
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
    let client_socket = tokio::net::TcpStream::connect((req_proxy.host.clone(), 443))
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
    let request: Request<Body> = build_request(req_proxy);

    println!("Starting an MPC TLS connection with the server");

    // Pass our request builder object to our client.
    let response = request_sender.send_request(request).await.unwrap();

    println!("Got a response from the server: {:?}", response);

    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::CREATED);
    println!("{:?}", response);

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
            // "Example Domain".as_bytes(),
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

#[derive(Debug, Deserialize, Clone)]
struct ProxyRequest {
    url: String,
    method: String,
    host: String,
    headers: Vec<Header>,
    body: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Header {
    key: String,
    value: String,
}

fn build_request(proxy_request: ProxyRequest) -> Request<Body> {
    let request_method = Method::from_str(&proxy_request.method[..]).unwrap();
    let request_body = proxy_request
        .clone()
        .body
        .map(|_| Body::from(proxy_request.body.clone().unwrap()))
        .unwrap_or_else(Body::empty);

    println!(
        "Building proxy request {:?} for MPC-TLS connection",
        proxy_request
    );

    let mut builder = Request::builder()
        .uri(proxy_request.url)
        .method(request_method)
        // add basic headers
        .header("Host", proxy_request.host)
        .header("Accept", "*/*")
        .header("Cache-Control", "no-cache")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity");

    for item in proxy_request.headers.iter() {
        builder = builder.header(item.key.clone(), item.value.clone());
    }

    builder.body(request_body).unwrap()
}
