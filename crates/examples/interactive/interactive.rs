use std::{
    env,
    net::{IpAddr, SocketAddr},
};

use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::transcript::Idx;
use tlsn_examples::get_crypto_provider_with_server_fixture;
use tlsn_prover::{state::Prove, Prover, ProverConfig};

use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use tlsn_verifier::{SessionInfo, Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

const SECRET: &str = "TLSNotary's private key 🤡";

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // we use SERVER_DOMAIN here to make sure it matches the domain in the test
    // server's certificate
    let uri = format!("https://{SERVER_DOMAIN}:{server_port}/formats/html");
    let server_ip: IpAddr = server_host.parse().expect("Invalid IP address");
    let server_addr = SocketAddr::from((server_ip, server_port));

    // Connect prover and verifier.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, &server_addr, &uri);
    let verifier = verifier(verifier_socket);
    let (_, (sent, received, _session_info)) = tokio::join!(prover, verifier);

    println!("Successfully verified {}", &uri);
    println!("Verified sent data:\n{}", bytes_to_redacted_string(&sent));
    println!(
        "Verified received data:\n{}",
        bytes_to_redacted_string(&received)
    );
}

#[instrument(skip(verifier_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
) {
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();

    // Create prover and connect to verifier.
    //
    // Perform the setup phase with the verifier.
    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(server_domain)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(MAX_SENT_DATA)
                    .max_recv_data(MAX_RECV_DATA)
                    .build()
                    .unwrap(),
            )
            .crypto_provider(get_crypto_provider_with_server_fixture())
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = tokio::net::TcpStream::connect(server_addr).await.unwrap();

    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("Secret", SECRET)
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    // Create proof for the Verifier.
    let mut prover = prover_task.await.unwrap().unwrap().start_prove();

    // Reveal parts of the transcript
    let idx_sent = redact_ranges_sent(&mut prover);
    let idx_recv = redact_ranges_received(&mut prover);
    prover.prove_transcript(idx_sent, idx_recv).await.unwrap();

    // Finalize.
    prover.finalize().await.unwrap()
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> (Vec<u8>, Vec<u8>, SessionInfo) {
    // Setup Verifier.
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let verifier_config = VerifierConfig::builder()
        .protocol_config_validator(config_validator)
        .crypto_provider(get_crypto_provider_with_server_fixture())
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    // Verify MPC-TLS and wait for (redacted) data.
    let (mut partial_transcript, session_info) = verifier.verify(socket.compat()).await.unwrap();
    partial_transcript.set_unauthed(0);

    // Check sent data: check host.
    let sent = partial_transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone()).expect("Verifier expected sent data");

    sent_data
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Verification failed: Expected host {}", SERVER_DOMAIN));

    // Check received data:
    let received = partial_transcript.received_unsafe().to_vec();
    let response = String::from_utf8(received.clone()).expect("Verifier expected received data");
    response
        .find("Herman Melville")
        .unwrap_or_else(|| panic!("Expected valid data from {}", SERVER_DOMAIN));

    // Check Session info: server name.
    assert_eq!(session_info.server_name.as_str(), SERVER_DOMAIN);

    (sent, received, session_info)
}

/// Redacts and reveals received data to the verifier.
fn redact_ranges_received(prover: &mut Prover<Prove>) -> Idx {
    let recv_transcript = prover.transcript().received();
    let recv_transcript_len = recv_transcript.len();

    // Get the received data as a string.
    let received_string = String::from_utf8(recv_transcript.to_vec()).unwrap();
    // Find the substring "illustrative".
    let start = received_string
        .find("Dick")
        .expect("Error: The substring 'Dick' was not found in the received data.");
    let end = start + "Dick".len();

    Idx::new([0..start, end..recv_transcript_len])
}

/// Redacts and reveals sent data to the verifier.
fn redact_ranges_sent(prover: &mut Prover<Prove>) -> Idx {
    let sent_transcript = prover.transcript().sent();
    let sent_transcript_len = sent_transcript.len();

    let sent_string = String::from_utf8(sent_transcript.to_vec()).unwrap();

    let secret_start = sent_string.find(SECRET).unwrap();

    // Reveal everything except for the SECRET.
    Idx::new([
        0..secret_start,
        secret_start + SECRET.len()..sent_transcript_len,
    ])
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}
