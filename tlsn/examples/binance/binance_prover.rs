// Runs a simple Prover which connects to the Notary and notarizes a request/response from
// example.com. The Prover then generates a proof and writes it to disk.

use http_body_util::Empty;
use http_body_util::BodyExt;
use hyper::server;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::digest::typenum::array;
use std::ops::Range;
use tlsn_core::{proof::TlsProof, transcript::get_value_ids};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn_examples::run_notary;
use tlsn_prover::tls::{state::Notarize, Prover, ProverConfig};
use serde_json::Value;
use reqwest::Error;

// Setting of the application server
const SERVER_DOMAIN: &str = "api.binance.com";
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
const API_KEY:&str = "SFn8TZJWUBJMAUk542nr6vpYlJUzkRkXmBrGye8pXfhrLkLcZnYMyyuNxSEBVs1O";
const API_SECRET:&str = "s0AiwZ6OpR8K76zde5JM25YFiu0PMqoCiGIT4VpCptJmHzZcgGjl4ctAZJYwZTdJ";

use std::{env, str};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use reqwest::Client;
use std::collections::HashMap;
use hex;

// Alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn create_signature(params: &HashMap<&str, String>, secret_key: &str) -> String {
    let query_string = params.iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<String>>()
        .join("&");

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(query_string.as_bytes());

    let result = mac.finalize();
    let signature_bytes = result.into_bytes();

    hex::encode(signature_bytes) // Convert to hex string
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();


    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 16);

    // Start a local simple notary service
    tokio::spawn(run_notary(notary_socket.compat()));

    // A Prover configuration
    let config = ProverConfig::builder()
        .id("binance_eth")
        .server_dns(SERVER_DOMAIN)
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
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
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

    // let request = Request::builder()
    //     .uri("/api/v3/time")
    //     .header("Host", SERVER_DOMAIN)
    //     .header("Accept", "*/*")
    //     // Using "identity" instructs the Server not to use compression for its HTTP response.
    //     // TLSNotary tooling does not support compression.
    //     .header("Accept-Encoding", "identity")
    //     .header("Connection", "close")
    //     .header("User-Agent", USER_AGENT)
    //     .body(Empty::<Bytes>::new())
    //     .unwrap();

    let res = reqwest::get("https://api.binance.com/api/v3/time").await;
    let json_value:Value = res.unwrap().json().await.unwrap();
    // println!("json value: {}", json_value);
    let server_time = json_value.get("serverTime").unwrap().to_string();
    // println!("serverTime: {}", server_time);
    let mut params = HashMap::new();
    params.insert("timestamp", server_time);
    params.insert("omitZeroBalances",String::from("true"));

    // Generate the signature
    let signature = create_signature(&params, API_SECRET);
    
    params.insert("signature", signature);

    let query_string: String = params.iter()
    .map(|(key, value)| format!("{}={}", key, value))
    .collect::<Vec<String>>()
    .join("&");

    // println!("query string: {}", query_string);

    let request = Request::builder()
        .uri(format!("/api/v3/account?{}", query_string))
        .header("Host", SERVER_DOMAIN)
        .header("X-MBX-APIKEY", API_KEY)
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
    // Read and print the response body

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    println!("Response body:\n{}", body_str);
    let json_value: Value = serde_json::from_str(&body_str).unwrap();
    let balances = json_value.get("balances").unwrap();

    // Find the asset "ETH"
    if let Some(eth) = balances.as_array().and_then(|assets| {
        assets.iter().find(|asset| asset["asset"] == "ETH")
    }) {
        // Extract the "free" amount of TON
        let free_eth = eth["free"].as_str().expect("Failed to get ETH free amount");
        println!("The amount of ETH is: {}", free_eth);
    } else {
        println!("ETH not found.");
    }

    // println!("Party {} has {} followers", party_index, followers_count);

    // The Prover task should be done now, so we can grab the Prover.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let prover = prover.start_notarize();

    // Build proof (with or without redactions)
    let redact = true;
    let proof = if !redact {
        build_proof_without_redactions(prover).await
    } else {
        build_proof_with_redactions(prover).await
    };

    // // Write the proof to a file
    let args: Vec<String> = std::env::args().collect();
    let file_dest = args.get(1).expect("Please provide a file destination as the second argument");
    let mut file = tokio::fs::File::create(file_dest).await.unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    println!("Notarization completed successfully!");
    println!("The proof has been written to `simple_proof.json`");
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
// Function to find ranges using regex
fn find_ranges_regex(seq: &[u8], private_regexes: &[&str]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    use regex::bytes::Regex;

    let mut private_ranges = Vec::new();

    for private_regex in private_regexes {
        let re = Regex::new(private_regex).unwrap();
        for cap in re.captures_iter(seq) {
            if let Some(private_part) = cap.get(1) {
                private_ranges.push(private_part.range());
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

async fn build_proof_without_redactions(mut prover: Prover<Notarize>) -> TlsProof {
    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();
    let sent_commitment = builder.commit_sent(&(0..sent_len)).unwrap();
    let recv_commitment = builder.commit_recv(&(0..recv_len)).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    proof_builder.reveal_by_id(sent_commitment).unwrap();
    proof_builder.reveal_by_id(recv_commitment).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
        //Ignoring because no redactions, thus no private ranges
        encodings: Vec::new(),
    }
}

async fn build_proof_with_redactions(mut prover: Prover<Notarize>) -> TlsProof {
    // Identify the ranges in the outbound data which contain data which we want to disclose
    let (sent_public_ranges, _) = find_ranges(
        prover.sent_transcript().data(),
        &[
            // Redact the value of the "User-Agent" header. It will NOT be disclosed.
            USER_AGENT.as_bytes(),
        ],
    );

    // Sensor all data in "balances"
    let (recv_public_ranges, _) = find_ranges_regex(
        prover.recv_transcript().data(),
        &[r#""balances":(\[(\{("|:|,|.|\w)+\})+\])"#]
    );
    // Create only proof for ETH "free" amount
    let (_, recv_private_ranges) = find_ranges_regex(
        prover.recv_transcript().data(),
        &[r#""ETH","free":"(\d+(\.\d+)?)"#]

    );
    println!("Received private ranges: {:?}", recv_private_ranges);

    let builder = prover.commitment_builder();

    // Commit to each range of the public outbound data which we want to disclose
    let sent_commitments: Vec<_> = sent_public_ranges
        .iter()
        .map(|range| builder.commit_sent(range).unwrap())
        .collect();
    // Commit to each range of the public inbound data which we want to disclose
    let recv_commitments: Vec<_> = recv_public_ranges
        .iter()
        .map(|range| builder.commit_recv(range).unwrap())
        .collect();

    println!("Committing to private ranges");
    let recv_private_commitments: Vec<_> = recv_private_ranges
        .iter()
        .map(|range| {
            println!("Committing to private range {:?}", range);
            builder.commit_recv(range).unwrap()
        })
        .collect();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    for commitment_id in sent_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }
    for commitment_id in recv_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }

    for commitment_id in recv_private_commitments {
        println!("Revealing private commitment {:?}", commitment_id);
        proof_builder.reveal_private_by_id(commitment_id).unwrap();
    }

    let substrings_proof = proof_builder.build().unwrap();
    println!("Received private ranges: {:?}", recv_private_ranges);
    // Generate the encodings for the private ranges
    let received_private_encodings =
        get_value_ids(&recv_private_ranges.into(), tlsn_core::Direction::Received)
            .map(|id| notarized_session.header().encode(&id))
            .collect::<Vec<_>>();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
        encodings: received_private_encodings,
    }
}
