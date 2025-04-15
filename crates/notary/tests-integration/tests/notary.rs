use async_tungstenite::{
    tokio::connect_async_with_tls_connector_and_config, tungstenite::protocol::WebSocketConfig,
};
use futures::future::join_all;
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Builder},
    rt::{TokioExecutor, TokioIo},
};
use notary_client::{Accepted, ClientError, NotarizationRequest, NotaryClient, NotaryConnection};
use rstest::rstest;
use rustls::{Certificate, RootCertStore};
use std::{string::String, time::Duration};
use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider};
use tlsn_prover::{Prover, ProverConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::sleep,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use tracing_subscriber::EnvFilter;
use ws_stream_tungstenite::WsStream;

use notary_server::{
    read_pem_file, run_server, AuthorizationProperties, LoggingProperties, NotarizationProperties,
    NotarizationSessionRequest, NotarizationSessionResponse, NotaryServerProperties,
    NotarySigningKeyProperties, ServerProperties, TLSProperties,
};

const MAX_SENT_DATA: usize = 1 << 13;
const MAX_RECV_DATA: usize = 1 << 13;

const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_DNS: &str = "tlsnotaryserver.io";
const NOTARY_CA_CERT_PATH: &str = "../server/fixture/tls/rootCA.crt";
const NOTARY_CA_CERT_BYTES: &[u8] = include_bytes!("../../server/fixture/tls/rootCA.crt");
const API_KEY: &str = "test_api_key_0";

fn get_server_config(
    port: u16,
    tls_enabled: bool,
    auth_enabled: bool,
    concurrency: usize,
) -> NotaryServerProperties {
    NotaryServerProperties {
        server: ServerProperties {
            name: NOTARY_DNS.to_string(),
            host: NOTARY_HOST.to_string(),
            port,
            html_info: "example html response".to_string(),
        },
        notarization: NotarizationProperties {
            max_sent_data: 1 << 13,
            max_recv_data: 1 << 14,
            timeout: 1800,
        },
        tls: TLSProperties {
            enabled: tls_enabled,
            private_key_pem_path: Some("../server/fixture/tls/notary.key".to_string()),
            certificate_pem_path: Some("../server/fixture/tls/notary.crt".to_string()),
        },
        notary_key: NotarySigningKeyProperties {
            private_key_pem_path: "../server/fixture/notary/notary.key".to_string(),
            public_key_pem_path: "../server/fixture/notary/notary.pub".to_string(),
        },
        logging: LoggingProperties {
            level: "DEBUG".to_string(),
            ..Default::default()
        },
        authorization: AuthorizationProperties {
            enabled: auth_enabled,
            whitelist_csv_path: Some("../server/fixture/auth/whitelist.csv".to_string()),
        },
        concurrency,
    }
}

async fn setup_config_and_server(
    sleep_ms: u64,
    port: u16,
    tls_enabled: bool,
    auth_enabled: bool,
    concurrency: usize,
) -> NotaryServerProperties {
    let notary_config = get_server_config(port, tls_enabled, auth_enabled, concurrency);

    // Abruptly closed connections will cause the server to log errors. We
    // prevent that by excluding the noisy modules from logging.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(
            "error,uid_mux::yamux=off,tlsn_verifier=off,notary_server::service::tcp=off",
        ))
        .try_init();
    // Note: since only one global subscriber is allowed for the entire
    // testsuite, the above filter will have an effect on all tests.

    let config = notary_config.clone();

    // Run the notary server
    tokio::spawn(async move {
        run_server(&config).await.unwrap();
    });

    // Sleep for a while to allow notary server to finish set up and start listening
    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

    notary_config
}

// Returns `NotaryClient` configured for proving over TCP.
fn tcp_prover_client(notary_config: NotaryServerProperties) -> NotaryClient {
    let mut notary_client_builder = NotaryClient::builder();

    notary_client_builder
        .host(&notary_config.server.host)
        .port(notary_config.server.port)
        .enable_tls(false);

    if notary_config.authorization.enabled {
        notary_client_builder.api_key(API_KEY);
    }

    notary_client_builder.build().unwrap()
}

// Tries to put the client in an `Accepted` state.
async fn accepted_client(client: NotaryClient) -> Result<Accepted, ClientError> {
    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    client.request_notarization(notarization_request).await
}

async fn tcp_prover(notary_config: NotaryServerProperties) -> (NotaryConnection, String) {
    let accepted = accepted_client(tcp_prover_client(notary_config))
        .await
        .unwrap();
    (accepted.io, accepted.id)
}

async fn tls_prover(notary_config: NotaryServerProperties) -> (NotaryConnection, String) {
    let mut certificate_file_reader = read_pem_file(NOTARY_CA_CERT_PATH).await.unwrap();
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(&certificate).unwrap();

    let notary_client = NotaryClient::builder()
        .host(&notary_config.server.name)
        .port(notary_config.server.port)
        .root_cert_store(root_cert_store)
        .build()
        .unwrap();

    let accepted = accepted_client(notary_client).await.unwrap();
    (accepted.io, accepted.id)
}

#[rstest]
// For `tls_without_auth` test to pass, one needs to add "<NOTARY_HOST> <NOTARY_DNS>" in /etc/hosts
// so that this test programme can resolve the self-named NOTARY_DNS to NOTARY_HOST IP successfully.
#[case::tls_without_auth({
    tls_prover(setup_config_and_server(100, 7047, true, false, 100).await)
})]
#[case::tcp_with_auth({
    tcp_prover(setup_config_and_server(100, 7048, false, true, 100).await)
})]
#[case::tcp_without_auth({
    tcp_prover(setup_config_and_server(100, 7049, false, false, 100).await)
})]
#[awt]
#[tokio::test]
#[ignore = "expensive"]
async fn test_tcp_prover<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    #[future]
    #[case]
    requested_notarization: (S, String),
) {
    let (notary_socket, _) = requested_notarization;

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let protocol_config = ProtocolConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    // Set up prover config.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(protocol_config)
        .crypto_provider(provider)
        .build()
        .unwrap();

    // Create a new Prover.
    let prover = Prover::new(prover_config)
        .setup(notary_socket.compat())
        .await
        .unwrap();

    // Connect to the Server.
    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);
    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover task to be run concurrently.
    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{}/echo", SERVER_DOMAIN))
        .method("POST")
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .body(Full::<Bytes>::new("echo".into()))
        .unwrap();

    debug!("Sending request to server: {:?}", request);

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let payload = response.into_body().collect().await.unwrap().to_bytes();
    debug!(
        "Received response from server: {:?}",
        &String::from_utf8_lossy(&payload)
    );

    server_task.await.unwrap().unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();

    let (sent_len, recv_len) = prover.transcript().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    let commit_config = builder.build().unwrap();

    prover.transcript_commit(commit_config);

    let request = RequestConfig::builder().build().unwrap();

    _ = prover.finalize(&request).await.unwrap();

    debug!("Done notarization!");
}

#[tokio::test]
#[ignore = "expensive"]
async fn test_websocket_prover() {
    // Notary server configuration setup
    let notary_config = setup_config_and_server(100, 7050, true, false, 100).await;
    let notary_host = notary_config.server.host.clone();
    let notary_port = notary_config.server.port;

    // Connect to the notary server via TLS-WebSocket
    // Try to avoid dealing with transport layer directly to mimic the limitation of
    // a browser extension that uses websocket
    //
    // Establish TLS setup for connections later
    let certificate =
        tokio_native_tls::native_tls::Certificate::from_pem(NOTARY_CA_CERT_BYTES).unwrap();
    let notary_tls_connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .add_root_certificate(certificate)
        .use_sni(false)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // Call the /session HTTP API to configure notarization and obtain session id
    let mut hyper_http_connector = HttpConnector::new();
    hyper_http_connector.enforce_http(false);
    let mut hyper_tls_connector =
        HttpsConnector::from((hyper_http_connector, notary_tls_connector.clone().into()));
    hyper_tls_connector.https_only(true);
    let https_client = Builder::new(TokioExecutor::new()).build(hyper_tls_connector);

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: notary_server::ClientType::Websocket,
        max_sent_data: Some(MAX_SENT_DATA),
        max_recv_data: Some(MAX_RECV_DATA),
    })
    .unwrap();

    let request = Request::builder()
        .uri(format!("https://{notary_host}:{notary_port}/session"))
        .method("POST")
        .header("Host", notary_host.clone())
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(payload)))
        .unwrap();

    debug!("Sending request");

    let response = https_client.request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Connect to the Notary via TLS-Websocket
    //
    // Note: This will establish a new TLS-TCP connection instead of reusing the
    // previous TCP connection used in the previous HTTP POST request because we
    // cannot claim back the tcp connection used in hyper client while using its
    // high level request function — there does not seem to have a crate that can
    // let you make a request without establishing TCP connection where you can
    // claim the TCP connection later after making the request
    let request = http::Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .uri(format!(
            "wss://{}:{}/notarize?sessionId={}",
            notary_host,
            notary_port,
            notarization_response.session_id.clone()
        ))
        .header("Host", notary_host.clone())
        .header("Sec-WebSocket-Key", uuid::Uuid::new_v4().to_string())
        .header("Sec-WebSocket-Version", "13")
        .header("Connection", "Upgrade")
        .header("Upgrade", "Websocket")
        .body(())
        .unwrap();

    let (notary_ws_stream, _) = connect_async_with_tls_connector_and_config(
        request,
        Some(notary_tls_connector.into()),
        Some(WebSocketConfig::default()),
    )
    .await
    .unwrap();

    // Wrap the socket with the adapter so that we get AsyncRead and AsyncWrite
    // implemented
    let notary_ws_socket = WsStream::new(notary_ws_stream);

    // Connect to the Server
    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);
    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let protocol_config = ProtocolConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    // Set up prover config.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(protocol_config)
        .crypto_provider(provider)
        .build()
        .unwrap();

    // Bind the Prover to the sockets
    let prover = Prover::new(prover_config)
        .setup(notary_ws_socket)
        .await
        .unwrap();
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover and Mux tasks to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{}/echo", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("POST")
        .body(Full::<Bytes>::new("echo".into()))
        .unwrap();

    debug!("Sending request to server: {:?}", request);

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let payload = response.into_body().collect().await.unwrap().to_bytes();
    debug!(
        "Received response from server: {:?}",
        &String::from_utf8_lossy(&payload)
    );

    server_task.await.unwrap().unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();

    let (sent_len, recv_len) = prover.transcript().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    let commit_config = builder.build().unwrap();

    prover.transcript_commit(commit_config);

    let request = RequestConfig::builder().build().unwrap();

    _ = prover.finalize(&request).await.unwrap();

    debug!("Done notarization!");
}

#[tokio::test]
async fn test_concurrency_limit() {
    const CONCURRENCY: usize = 5;

    let notary_config = setup_config_and_server(100, 7051, false, false, CONCURRENCY).await;

    async fn do_test(config: NotaryServerProperties) -> Vec<(NotaryConnection, String)> {
        // Start notarization requests in parallel.
        let connections = (0..CONCURRENCY).map(|_| tcp_prover(config.clone()));

        // Wait for all requests to become accepted.
        let mut connections = join_all(connections).await;

        // Start a new request which will time out.
        let mut client = tcp_prover_client(config.clone());
        client.request_timeout(1);
        assert_eq!(accepted_client(client.clone()).await.err().unwrap().to_string(), "client error: Internal, source: Some(\"Timed out while waiting for server to accept notarization request\")");

        // Close one of the connections.
        connections.pop().unwrap().0.shutdown().await.unwrap();

        // Start a new request which will be accepted this time.
        let accepted = accepted_client(client).await.unwrap();
        connections.push((accepted.io, accepted.id));

        connections
    }

    let connections = do_test(notary_config.clone()).await;
    // Close all connections.
    for mut c in connections {
        c.0.shutdown().await.unwrap();
    }

    // Test again to make sure the server's semaphore was restored to the initial
    // state.
    _ = do_test(notary_config).await;
}

#[tokio::test]
async fn test_notarization_request_retry() {
    const CONCURRENCY: usize = 5;

    let config = setup_config_and_server(100, 7052, false, false, CONCURRENCY).await;

    // Max out the concurrency limit.
    let connections = (0..CONCURRENCY).map(|_| tcp_prover(config.clone()));
    let mut connections = join_all(connections).await;

    // Start a new request which will retry every second.
    let mut client = tcp_prover_client(config.clone());
    client.request_retry_override(1);
    let client_fut = accepted_client(client.clone());
    tokio::pin!(client_fut);

    tokio::select! {
        _ = &mut client_fut => panic!("Expected timeout to complete first"),
        _ = sleep(Duration::from_secs(2)) => {}
    }

    // Close one of the connections.
    connections.pop().unwrap().0.shutdown().await.unwrap();

    // Now the request will be accepted.
    tokio::select! {
        _ = client_fut => {},
        _ = sleep(Duration::from_secs(2)) => panic!("Expected client future to complete first")
    }
}
