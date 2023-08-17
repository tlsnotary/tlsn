use eyre::Result;
use futures::AsyncWriteExt;
use hyper::{body::to_bytes, client::conn::Parts, Body, Request, StatusCode};
use rustls::{Certificate, ClientConfig, RootCertStore};
use std::{
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    ops::Range,
    sync::Arc,
};
use tokio::{fs::File, io::AsyncWriteExt as _, net::TcpStream};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use notary_server::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use tlsn_prover::{bind_prover, ProverConfig};

const SERVER_DOMAIN: &str = "example.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;
const NOTARY_CA_CERT_PATH: &str = "./rootCA.crt";
const MAX_TRANSCRIPT_SIZE: usize = 16384;

/// Runs a simple Prover which connects to the Notary and notarizes a request/response from
/// example.com. The Prover then generates a proof and writes it to disk.
///
/// Note that the Notary server must be already listening on NOTARY_HOST:NOTARY_PORT
/// (see README.md "Starting a notary server")
#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Establish an encrypted connection with the Notary
    let (notary_socket, session_id) = connect_to_notary().await;
    println!("Connected to the Notary");

    // A Prover configuration using the session_id returned by the Notary
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .max_transcript_size(MAX_TRANSCRIPT_SIZE)
        .build()
        .unwrap();

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to the sockets.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    let (mpc_tls_connection, prover_fut, notary_fut) =
        bind_prover(config, client_socket.compat(), notary_socket.compat())
            .await
            .unwrap();

    // Spawn the Notary connection task and the Prover task to be run concurrently
    tokio::spawn(notary_fut);
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
        .uri(format!("https://{SERVER_DOMAIN}"))
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
    let mut prover = prover_task.await.unwrap().unwrap();

    // Prepare for selective disclosure.

    // Identify the ranges in the outbound data which contain data which we want to disclose
    let (public_ranges, _) = find_ranges(
        prover.sent_transcript().data(),
        &[
            // Redact the value of the "User-Agent" header. It will NOT be disclosed.
            USER_AGENT.as_bytes(),
        ],
    );

    // Commit to each range of the outbound data which we want to disclose
    for range in public_ranges.iter() {
        prover.add_commitment_sent(range.clone()).unwrap();
    }

    // Commit to all inbound data in one shot, as we don't need to redact anything in it
    let recv_len = prover.recv_transcript().data().len();
    prover.add_commitment_recv(0..recv_len as u32).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let session_proof = notarized_session.session_proof();
    let ids = (0..notarized_session.data().commitments().len()).collect();
    let substrings_proof = notarized_session.generate_substring_proof(ids).unwrap();

    // Write the proof to a file in the format expected by `simple_verifier.rs`
    let mut file = tokio::fs::File::create("proof.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(&(&session_proof, &substrings_proof, &SERVER_DOMAIN))
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    println!("Notarization completed successfully!");
    println!("The proof has been written to proof.json");
}

/// Connects to the Notary and sets up a notarization session.
///
/// Returns a socket used to communicate with the Notary and a notarization session id.
async fn connect_to_notary() -> (TlsStream<TcpStream>, String) {
    // Connect to the Notary via TLS

    // Since the Notary will present a self-signed certificate, we add the CA which signed the
    // certificate to the trusted list
    let mut certificate_file_reader = read_pem_file(NOTARY_CA_CERT_PATH).await.unwrap();
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_store = RootCertStore::empty();
    root_store.add(&certificate).unwrap();

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let notary_connector = TlsConnector::from(Arc::new(client_config));

    // Establish a TCP connection to the notary
    let notary_socket = tokio::net::TcpStream::connect(SocketAddr::new(
        IpAddr::V4(NOTARY_HOST.parse().unwrap()),
        NOTARY_PORT,
    ))
    .await
    .unwrap();

    // Wrap the TCP connection in TLS
    // Tell the TLS backend to expect that the Notary's cert was issued to "tlsnotaryserver.io"
    let notary_tls_socket = notary_connector
        .connect("tlsnotaryserver.io".try_into().unwrap(), notary_socket)
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection and start the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::handshake(notary_tls_socket)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Tcp,
        max_transcript_size: Some(MAX_TRANSCRIPT_SIZE),
    })
    .unwrap();
    let request = Request::builder()
        .uri(format!("https://{NOTARY_HOST}:{NOTARY_PORT}/session"))
        .method("POST")
        .header("Host", NOTARY_HOST.clone())
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    debug!("Sending configuration request");

    let configuration_response = request_sender.send_request(request).await.unwrap();

    debug!("Sent configuration request");

    assert!(configuration_response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let configuration_response = to_bytes(configuration_response.into_body())
        .await
        .unwrap()
        .to_vec();
    let configuration_response = serde_json::from_str::<NotarizationSessionResponse>(
        &String::from_utf8_lossy(&configuration_response),
    )
    .unwrap();

    debug!("Configuration response: {:?}", configuration_response,);

    // Request the notary to prepare for notarization via HTTP, where the underlying TCP connection
    // will be extracted later
    let request = Request::builder()
        .uri(format!("https://{NOTARY_HOST}:{NOTARY_PORT}/notarize"))
        .method("GET")
        .header("Host", NOTARY_HOST)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .header("X-Session-Id", configuration_response.session_id.clone())
        .body(Body::empty())
        .unwrap();

    debug!("Sending notarization preparation request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent notarization preparation request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    debug!("Switched protocol OK");

    // Claim back the TLS socket after HTTP exchange is done
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

    (notary_tls_socket, configuration_response.session_id)
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<u32>>, Vec<Range<u32>>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx as u32..(idx + w.len()) as u32);
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

    if last_end < seq.len() as u32 {
        public_ranges.push(last_end..seq.len() as u32);
    }

    (public_ranges, private_ranges)
}

/// Read a PEM-formatted file and return its buffer reader
async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}
