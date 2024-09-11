use async_tungstenite::{tokio::connect_async_with_config, tungstenite::protocol::WebSocketConfig};
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use regex::Regex;
use tlsn_core::Direction;
use tlsn_prover::tls::{state::Prove, Prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use ws_stream_tungstenite::WsStream;

const TRACING_FILTER: &str = "INFO";

const VERIFIER_HOST: &str = "localhost";
const VERIFIER_PORT: u16 = 9816;

const SECRET: &str = "TLSNotary's private key 🤡";
/// Make sure the following url's domain is the same as SERVER_DOMAIN on the verifier side
const SERVER_URL: &str = "https://swapi.dev/api/people/1";
/// Make sure this is the same on the verifier side
const VERIFICATION_SESSION_ID: &str = "interactive-verifier-demo";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| TRACING_FILTER.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    run_prover(
        VERIFIER_HOST,
        VERIFIER_PORT,
        SERVER_URL,
        VERIFICATION_SESSION_ID,
    )
    .await;
}

async fn run_prover(
    verifier_host: &str,
    verifier_port: u16,
    server_uri: &str,
    verification_session_id: &str,
) {
    info!("Sending websocket request...");
    let request = http::Request::builder()
        .uri(format!("ws://{}:{}/verify", verifier_host, verifier_port,))
        .header("Host", verifier_host)
        .header("Sec-WebSocket-Key", uuid::Uuid::new_v4().to_string())
        .header("Sec-WebSocket-Version", "13")
        .header("Connection", "Upgrade")
        .header("Upgrade", "Websocket")
        .body(())
        .unwrap();

    let (verifier_ws_stream, _) =
        connect_async_with_config(request, Some(WebSocketConfig::default()))
            .await
            .unwrap();

    info!("Websocket connection established!");
    let verifier_ws_socket = WsStream::new(verifier_ws_stream);
    prover(verifier_ws_socket, server_uri, verification_session_id).await;
    info!("Proving is successful!");
}

async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    uri: &str,
    id: &str,
) {
    debug!("Starting proving...");

    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();
    let server_port = uri.port_u16().unwrap_or(443);

    // Create prover and connect to verifier.
    let prover = Prover::new(
        ProverConfig::builder()
            .id(id)
            .server_dns(server_domain)
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    // Connect to TLS Server.
    info!("Connect to TLS Server");
    let tls_client_socket = tokio::net::TcpStream::connect((server_domain, server_port))
        .await
        .unwrap();
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response.
    info!("Send Request and wait for Response");
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("Secret", SECRET)
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();

    debug!("TLS response: {:?}", response);
    assert!(response.status() == StatusCode::OK);

    // Close TLS Connection.
    // let tls_connection = connection_task.await.unwrap().unwrap().io.into_inner();
    // debug!("TLS connection: {:?}", tls_connection);
    // tls_connection.compat().close().await.unwrap();
    // info!("TLS Connection closed");

    // Create proof for the Verifier.
    info!("Create proof for the Verifier");
    let mut prover = prover_task.await.unwrap().unwrap().start_prove();
    redact_and_reveal_sent_data(&mut prover);
    redact_and_reveal_received_data(&mut prover);
    prover.prove().await.unwrap();

    // Finalize.
    info!("Finalize prover");
    prover.finalize().await.unwrap()
}

/// Redacts and reveals received data to the verifier.
fn redact_and_reveal_received_data(prover: &mut Prover<Prove>) {
    let recv_transcript_len = prover.recv_transcript().data().len();

    // Get the homeworld from the received data.
    let received_string = String::from_utf8(prover.recv_transcript().data().to_vec()).unwrap();
    debug!("Received data: {}", received_string);
    let re = Regex::new(r#""homeworld"\s?:\s?"(.*?)""#).unwrap();
    let homeworld_match = re.captures(&received_string).unwrap().get(1).unwrap();

    // Reveal everything except for the homeworld.
    _ = prover.reveal(0..homeworld_match.start(), Direction::Received);
    _ = prover.reveal(
        homeworld_match.end()..recv_transcript_len,
        Direction::Received,
    );
}

/// Redacts and reveals sent data to the verifier.
fn redact_and_reveal_sent_data(prover: &mut Prover<Prove>) {
    let sent_transcript_len = prover.sent_transcript().data().len();

    let sent_string = String::from_utf8(prover.sent_transcript().data().to_vec()).unwrap();
    let secret_start = sent_string.find(SECRET).unwrap();

    debug!("Send data: {}", sent_string);

    // Reveal everything except for the SECRET.
    _ = prover.reveal(0..secret_start, Direction::Sent);
    _ = prover.reveal(
        secret_start + SECRET.len()..sent_transcript_len,
        Direction::Sent,
    );
}
