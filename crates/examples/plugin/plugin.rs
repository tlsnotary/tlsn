use async_tungstenite::{tokio::connect_async_with_config, tungstenite::protocol::WebSocketConfig};
use clap::Parser;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::{client::legacy::{connect::HttpConnector}, rt::{TokioExecutor, TokioIo}};
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use notary_common::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use rangeset::RangeSet;
use spansy::{
    http::parse_response,
    json::{self},
    Spanned,
};
use std::env;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::ProveConfig;
use tlsn_prover::{Prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info};
use ws_stream_tungstenite::WsStream;

const SECRET: &str = "TLSNotary's private key 🤡";
const SERVER_URL: &str = "https://raw.githubusercontent.com/tlsnotary/tlsn/refs/tags/v0.1.0-alpha.11/crates/server-fixture/server/src/data/1kb.json";

#[derive(clap::ValueEnum, Clone, Default, Debug)]
pub enum ProverType {
    #[default]
    Tcp,
    Ws,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// What data to notarize.
    #[clap(default_value_t, value_enum)]
    prover_type: ProverType,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let verifier_host: String = env::var("VERIFIER_HOST").unwrap_or("127.0.0.1".into());
    let verifier_port: u16 = env::var("VERIFIER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(7047);

    let args = Args::parse();
    match args.prover_type {
        ProverType::Tcp => run_tcp_prover(&verifier_host, verifier_port).await,
        ProverType::Ws => run_ws_prover(&verifier_host, verifier_port).await,
    }
}

async fn run_ws_prover(verifier_host: &str, verifier_port: u16) {
    info!("Running websocket prover...");

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Websocket,
        max_sent_data: Some(tlsn_examples::MAX_SENT_DATA),
        max_recv_data: Some(tlsn_examples::MAX_RECV_DATA),
    })
    .unwrap();

    let session_request = Request::builder()
        .uri(format!("http://{verifier_host}:{verifier_port}/session"))
        .method("POST")
        .header("Host", verifier_host)
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(payload)))
        .unwrap();

    let hyper_http_connector: HttpConnector = HttpConnector::new();
    let http_client = hyper_util::client::legacy::Builder::new(TokioExecutor::new()).build(hyper_http_connector);
    let response = http_client.request(session_request).await.unwrap();
    assert!(response.status() == StatusCode::OK);
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Session request response: {:?}", notarization_response,);

    let verification_request = hyper::Request::builder()
        .uri(format!("ws://{verifier_host}:{verifier_port}/notarize?sessionId={}", notarization_response.session_id))
        .header("Host", verifier_host)
        .header("Sec-WebSocket-Key", uuid::Uuid::new_v4().to_string())
        .header("Sec-WebSocket-Version", "13")
        .header("Connection", "Upgrade")
        .header("Upgrade", "Websocket")
        .body(())
        .unwrap();

    let (verifier_ws_stream, _) =
        connect_async_with_config(verification_request, Some(WebSocketConfig::default()))
            .await
            .unwrap();

    info!("Websocket connection established!");
    let verifier_ws_socket = WsStream::new(verifier_ws_stream);
    prover(verifier_ws_socket, SERVER_URL).await;
    info!("Websocket proving is successful!");
}

async fn run_tcp_prover(verifier_host: &str, verifier_port: u16) {
    info!("Running tcp prover...");

    // Build a tcp client to connect to the verifier server.
    let verifier_client = NotaryClient::builder()
        .host(verifier_host)
        .port(verifier_port)
        // WARNING: Always use TLS to connect to verifier server, except if verifier is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and verification to the verifier server.
    let verification_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(tlsn_examples::MAX_SENT_DATA)
        .max_recv_data(tlsn_examples::MAX_RECV_DATA)
        .build()
        .unwrap();

    let Accepted {
        io: verifier_connection,
        id: _session_id,
        ..
    } = verifier_client
        .request_notarization(verification_request)
        .await
        .expect("Could not connect to verifier. Make sure it is running.");

    info!("Tcp connection established!");
    prover(verifier_connection, SERVER_URL).await;
    info!("Tcp proving is successful!");
}

async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(verifier_socket: T, uri: &str) {
    debug!("Starting proving...");

    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();
    let server_port = uri.port_u16().unwrap_or(443);

    // Create prover and connect to verifier.
    //
    // Perform the setup phase with the verifier.
    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(server_domain)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(tlsn_examples::MAX_SENT_DATA)
                    .max_recv_data(tlsn_examples::MAX_RECV_DATA)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = tokio::net::TcpStream::connect((server_domain, server_port))
        .await
        .unwrap();

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

    // Create proof for the Verifier.
    let mut prover = prover_task.await.unwrap().unwrap();

    let mut builder: tlsn_core::ProveConfigBuilder<'_> = ProveConfig::builder(prover.transcript());

    // Reveal the DNS name.
    builder.server_identity();

    let sent_rangeset = redact_and_reveal_sent_data(prover.transcript().sent());
    let _ = builder.reveal_sent(&sent_rangeset);

    let recv_rangeset = redact_and_reveal_received_data(prover.transcript().received());
    let _ = builder.reveal_recv(&recv_rangeset);

    let config = builder.build().unwrap();

    prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();
}

/// Redacts and reveals received data to the verifier.
fn redact_and_reveal_received_data(recv_transcript: &[u8]) -> RangeSet<usize> {
    // Get the some information from the received data.
    let received_string = String::from_utf8(recv_transcript.to_vec()).unwrap();
    debug!("Received data: {}", received_string);
    let resp = parse_response(recv_transcript).unwrap();
    let body = resp.body.unwrap();
    let mut json = json::parse_slice(body.as_bytes()).unwrap();
    json.offset(body.content.span().indices().min().unwrap());

    let name = json.get("information.name").expect("name field not found");

    let street = json
        .get("information.address.street")
        .expect("street field not found");

    let name_start = name.span().indices().min().unwrap() - 9; // 9 is the length of "name: "
    let name_end = name.span().indices().max().unwrap() + 1; // include `"`
    let street_start = street.span().indices().min().unwrap() - 11; // 11 is the length of "street: "
    let street_end = street.span().indices().max().unwrap() + 1; // include `"`

    [name_start..name_end + 1, street_start..street_end + 1].into()
}

/// Redacts and reveals sent data to the verifier.
fn redact_and_reveal_sent_data(sent_transcript: &[u8]) -> RangeSet<usize> {
    let sent_transcript_len = sent_transcript.len();

    let sent_string: String = String::from_utf8(sent_transcript.to_vec()).unwrap();
    let secret_start = sent_string.find(SECRET).unwrap();

    debug!("Send data: {}", sent_string);

    // Reveal everything except for the SECRET.
    [
        0..secret_start,
        secret_start + SECRET.len()..sent_transcript_len,
    ]
    .into()
}
