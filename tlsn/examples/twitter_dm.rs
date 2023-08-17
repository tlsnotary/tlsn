/// This prover implementation talks to the notary server implemented in https://github.com/tlsnotary/notary-server, instead of the simple_notary.rs in this example directory
use eyre::Result;
use futures::AsyncWriteExt;
use hyper::{body::to_bytes, client::conn::Parts, Body, Request, StatusCode};
use rustls::{Certificate, ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    ops::Range,
    sync::Arc,
};
use tokio::{fs::File, io::AsyncWriteExt as _};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use tlsn_prover::{bind_prover, ProverConfig};

// Setting of the application server
const SERVER_DOMAIN: &str = "twitter.com";
const ROUTE: &str = "i/api/1.1/dm/conversation";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

// Setting of the notary server — make sure these are the same with those in the notary-server repository used (https://github.com/tlsnotary/notary-server)
const NOTARY_DOMAIN: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;
const NOTARY_CA_CERT_PATH: &str = "./rootCA.crt";

// Configuration of notarization
const NOTARY_MAX_TRANSCRIPT_SIZE: usize = 16384;

/// Response object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
    pub session_id: String,
}

/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
    pub client_type: ClientType,
    /// Maximum transcript size in bytes
    pub max_transcript_size: Option<usize>,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    /// Client that has access to the transport layer
    Tcp,
    /// Client that cannot directly access transport layer, e.g. browser extension
    Websocket,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load secret variables frome environment for twitter server connection
    dotenv::dotenv().ok();
    let conversation_id = env::var("CONVERSATION_ID").unwrap();
    let client_uuid = env::var("CLIENT_UUID").unwrap();
    let auth_token = env::var("AUTH_TOKEN").unwrap();
    let access_token = env::var("ACCESS_TOKEN").unwrap();
    let csrf_token = env::var("CSRF_TOKEN").unwrap();

    // Connect to the Notary via TLS-TCP
    let mut certificate_file_reader = read_pem_file(NOTARY_CA_CERT_PATH).await.unwrap();
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_store = RootCertStore::empty();
    root_store.add(&certificate).unwrap();

    let client_notary_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

    let notary_socket = tokio::net::TcpStream::connect(SocketAddr::new(
        IpAddr::V4(NOTARY_DOMAIN.parse().unwrap()),
        NOTARY_PORT,
    ))
    .await
    .unwrap();

    let notary_tls_socket = notary_connector
        // Require the domain name of notary server to be the same as that in the server cert
        .connect("tlsnotaryserver.io".try_into().unwrap(), notary_socket)
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection to send request to the /session endpoint to configure notarization and obtain session id
    let (mut request_sender, connection) = hyper::client::conn::handshake(notary_tls_socket)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Tcp,
        max_transcript_size: Some(NOTARY_MAX_TRANSCRIPT_SIZE),
    })
    .unwrap();
    let request = Request::builder()
        .uri(format!("https://{NOTARY_DOMAIN}:{NOTARY_PORT}/session"))
        .method("POST")
        .header("Host", NOTARY_DOMAIN.clone())
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
    let payload = to_bytes(configuration_response.into_body())
        .await
        .unwrap()
        .to_vec();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
    let request = Request::builder()
        .uri(format!("https://{NOTARY_DOMAIN}:{NOTARY_PORT}/notarize"))
        .method("GET")
        .header("Host", NOTARY_DOMAIN)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .header("X-Session-Id", notarization_response.session_id.clone())
        .body(Body::empty())
        .unwrap();

    debug!("Sending notarization request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent notarization request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    debug!("Switched protocol OK");

    // Claim back the TLS socket after HTTP exchange is done
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

    // Connect to the Server
    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(notarization_response.session_id)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to the sockets
    let (tls_connection, prover_fut, mux_fut) =
        bind_prover(config, client_socket.compat(), notary_tls_socket.compat())
            .await
            .unwrap();

    // Spawn the Prover and Mux tasks to be run concurrently
    tokio::spawn(mux_fut);
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .uri(format!(
            "https://{SERVER_DOMAIN}/{ROUTE}/{conversation_id}.json"
        ))
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .header("Authorization", format!("Bearer {access_token}"))
        .header(
            "Cookie",
            format!("auth_token={auth_token}; ct0={csrf_token}"),
        )
        .header("Authority", SERVER_DOMAIN)
        .header("X-Twitter-Auth-Type", "OAuth2Session")
        .header("x-twitter-active-user", "yes")
        .header("X-Client-Uuid", client_uuid)
        .header("X-Csrf-Token", csrf_token.clone())
        .body(Body::empty())
        .unwrap();

    debug!("Sending request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK);

    debug!("Request OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // Close the connection to the server
    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();
    client_socket.close().await.unwrap();

    // The Prover task should be done now, so we can grab it.
    let mut prover = prover_task.await.unwrap().unwrap();

    // Identify the ranges in the transcript that contain secrets
    let (public_ranges, private_ranges) = find_ranges(
        prover.sent_transcript().data(),
        &[
            access_token.as_bytes(),
            auth_token.as_bytes(),
            csrf_token.as_bytes(),
        ],
    );

    // Commit to the outbound transcript, isolating the data that contain secrets
    for range in public_ranges.iter().chain(private_ranges.iter()) {
        prover.add_commitment_sent(range.clone()).unwrap();
    }

    // Commit to the full received transcript in one shot, as we don't need to redact anything
    let recv_len = prover.recv_transcript().data().len();
    prover.add_commitment_recv(0..recv_len as u32).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("twitter_dm.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(&notarized_session)
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], sub_seq: &[&[u8]]) -> (Vec<Range<u32>>, Vec<Range<u32>>) {
    let mut private_ranges = Vec::new();
    for s in sub_seq {
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
