use async_tungstenite::{
    tokio::connect_async_with_tls_connector_and_config, tungstenite::protocol::WebSocketConfig,
};
use futures::AsyncWriteExt;
use hyper::{body::to_bytes, client::HttpConnector, Body, Client, Request, StatusCode};
use hyper_tls::HttpsConnector;
use rstest::rstest;
use std::time::Duration;
use tls_core::anchors::RootCertStore as TlsClientRootCertStore;
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tlsn_notary_client::client::NotaryClient;
use tlsn_prover::tls::{state::Setup, Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use ws_stream_tungstenite::WsStream;

use notary_server::{
    run_server, AuthorizationProperties, LoggingProperties, NotarizationProperties,
    NotarizationSessionRequest, NotarizationSessionResponse, NotaryServerProperties,
    NotarySigningKeyProperties, ServerProperties, TLSProperties,
};

const NOTARY_CA_CERT_BYTES: &[u8] = include_bytes!("../fixture/tls/rootCA.crt");
const MAX_SENT: usize = 1 << 13;
const MAX_RECV: usize = 1 << 13;
const API_KEY: &str = "test_api_key_0";

fn get_server_config(port: u16, tls_enabled: bool, auth_enabled: bool) -> NotaryServerProperties {
    NotaryServerProperties {
        server: ServerProperties {
            name: "tlsnotaryserver.io".to_string(),
            host: "127.0.0.1".to_string(),
            port,
            html_info: "example html response".to_string(),
        },
        notarization: NotarizationProperties {
            max_transcript_size: 1 << 14,
        },
        tls: TLSProperties {
            enabled: tls_enabled,
            private_key_pem_path: "./fixture/tls/notary.key".to_string(),
            certificate_pem_path: "./fixture/tls/notary.crt".to_string(),
        },
        notary_key: NotarySigningKeyProperties {
            private_key_pem_path: "./fixture/notary/notary.key".to_string(),
            public_key_pem_path: "./fixture/notary/notary.pub".to_string(),
        },
        logging: LoggingProperties {
            level: "DEBUG".to_string(),
            filter: None,
        },
        authorization: AuthorizationProperties {
            enabled: auth_enabled,
            whitelist_csv_path: "./fixture/auth/whitelist.csv".to_string(),
        },
    }
}

async fn setup_config_and_server(
    sleep_ms: u64,
    port: u16,
    tls_enabled: bool,
    auth_enabled: bool,
) -> NotaryServerProperties {
    let notary_config = get_server_config(port, tls_enabled, auth_enabled);

    let _ = tracing_subscriber::fmt::try_init();

    let config = notary_config.clone();

    // Run the notary server
    tokio::spawn(async move {
        run_server(&config).await.unwrap();
    });

    // Sleep for a while to allow notary server to finish set up and start listening
    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

    notary_config
}

fn get_server_root_cert_store() -> TlsClientRootCertStore {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    root_store
}

async fn tcp_prover(
    notary_config: NotaryServerProperties,
    server_root_store: TlsClientRootCertStore,
) -> Prover<Setup> {
    let notary_client = NotaryClient::builder()
        .host(&notary_config.server.host)
        .port(notary_config.server.port)
        .max_sent_data(MAX_SENT)
        .max_recv_data(MAX_RECV)
        // set this to None to turn off TLS
        .notary_dns(None)
        // set this to None to turn off TLS
        .notary_root_cert_store(None)
        .server_dns(SERVER_DOMAIN)
        .server_root_cert_store(server_root_store)
        .build()
        .unwrap();

    notary_client.setup_tcp_prover().await.unwrap()
}

async fn tls_prover(
    notary_config: NotaryServerProperties,
    server_root_store: TlsClientRootCertStore,
) -> Prover<Setup> {
    let mut notary_client_builder = NotaryClient::builder();

    notary_client_builder
        .host(&notary_config.server.host)
        .port(notary_config.server.port)
        .max_sent_data(MAX_SENT)
        .max_recv_data(MAX_RECV)
        .server_dns(SERVER_DOMAIN)
        .server_root_cert_store(server_root_store);

    if notary_config.authorization.enabled {
        notary_client_builder.api_key(API_KEY);
    }

    let notary_client = notary_client_builder.build().unwrap();

    notary_client.setup_tls_prover().await.unwrap()
}

#[rstest]
#[case::with_tls_and_auth(
    tls_prover(setup_config_and_server(100, 7047, true, true).await, get_server_root_cert_store())
)]
#[case::with_tls_and_no_auth(
    tls_prover(setup_config_and_server(100, 7048, true, false).await, get_server_root_cert_store())
)]
#[case::without_tls(
    tcp_prover(setup_config_and_server(100, 7049, false, false).await, get_server_root_cert_store())
)]
#[awt]
#[tokio::test]
async fn test_tcp_prover(
    #[future]
    #[case]
    prover: Prover<Setup>,
) {
    // Connect to the Server
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
        .await
        .unwrap();

    let connection_task = tokio::spawn(connection.without_shutdown());

    let request = Request::builder()
        .uri(format!("https://{}/echo", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("POST")
        .body(Body::from("echo"))
        .unwrap();

    debug!("Sending request to server: {:?}", request);

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    debug!(
        "Received response from server: {:?}",
        String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
    );

    let mut server_tls_conn = server_task.await.unwrap().unwrap();

    // Make sure the server closes cleanly (sends close notify)
    server_tls_conn.close().await.unwrap();

    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

    client_socket.close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();

    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    _ = prover.finalize().await.unwrap();

    debug!("Done notarization!");
}

#[tokio::test]
async fn test_websocket_prover() {
    // Notary server configuration setup
    let notary_config = setup_config_and_server(100, 7050, true, false).await;
    let notary_host = notary_config.server.host.clone();
    let notary_port = notary_config.server.port;

    // Connect to the notary server via TLS-WebSocket
    // Try to avoid dealing with transport layer directly to mimic the limitation of a browser extension that uses websocket
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
    let https_client = Client::builder().build::<_, hyper::Body>(hyper_tls_connector);

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: notary_server::ClientType::Websocket,
        max_sent_data: Some(MAX_SENT),
        max_recv_data: Some(MAX_RECV),
    })
    .unwrap();

    let request = Request::builder()
        .uri(format!("https://{notary_host}:{notary_port}/session"))
        .method("POST")
        .header("Host", notary_host.clone())
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    debug!("Sending request");

    let response = https_client.request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Connect to the Notary via TLS-Websocket
    //
    // Note: This will establish a new TLS-TCP connection instead of reusing the previous TCP connection
    // used in the previous HTTP POST request because we cannot claim back the tcp connection used in hyper
    // client while using its high level request function — there does not seem to have a crate that can let you
    // make a request without establishing TCP connection where you can claim the TCP connection later after making the request
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

    // Wrap the socket with the adapter so that we get AsyncRead and AsyncWrite implemented
    let notary_ws_socket = WsStream::new(notary_ws_stream);

    // Connect to the Server
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    // Basic default prover config — use the responded session id from notary server
    let prover_config = ProverConfig::builder()
        .id(notarization_response.session_id)
        .server_dns(SERVER_DOMAIN)
        .root_cert_store(root_store)
        .max_sent_data(MAX_SENT)
        .max_recv_data(MAX_RECV)
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

    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
        .await
        .unwrap();

    let connection_task = tokio::spawn(connection.without_shutdown());

    let request = Request::builder()
        .uri(format!("https://{}/echo", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("POST")
        .body(Body::from("echo"))
        .unwrap();

    debug!("Sending request to server: {:?}", request);

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    debug!(
        "Received response from server: {:?}",
        String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
    );

    let mut server_tls_conn = server_task.await.unwrap().unwrap();

    // Make sure the server closes cleanly (sends close notify)
    server_tls_conn.close().await.unwrap();

    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

    client_socket.close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();

    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    _ = prover.finalize().await.unwrap();

    debug!("Done notarization!");
}
