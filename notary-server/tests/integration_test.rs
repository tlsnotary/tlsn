use async_tungstenite::{
    tokio::connect_async_with_tls_connector_and_config, tungstenite::protocol::WebSocketConfig,
};
use futures::AsyncWriteExt;
use hyper::{
    body::to_bytes,
    client::{conn::Parts, HttpConnector},
    Body, Client, Request, StatusCode,
};
use hyper_tls::HttpsConnector;
use rustls::{Certificate, ClientConfig, RootCertStore};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use ws_stream_tungstenite::WsStream;

use notary_server::{
    read_pem_file, run_server, NotarizationProperties, NotarizationSessionRequest,
    NotarizationSessionResponse, NotaryServerProperties, NotarySignatureProperties,
    ServerProperties, TLSSignatureProperties, TracingProperties,
};

const NOTARY_CA_CERT_PATH: &str = "./fixture/tls/rootCA.crt";
const NOTARY_CA_CERT_BYTES: &[u8] = include_bytes!("../fixture/tls/rootCA.crt");

async fn setup_config_and_server(
    sleep_ms: u64,
    port: u16,
    use_tls: bool,
) -> NotaryServerProperties {
    let notary_config = NotaryServerProperties {
        server: ServerProperties {
            name: "tlsnotaryserver.io".to_string(),
            host: "127.0.0.1".to_string(),
            port,
        },
        notarization: NotarizationProperties {
            max_transcript_size: 1 << 14,
        },
        tls_signature: if use_tls {
            Some(TLSSignatureProperties {
                private_key_pem_path: "./fixture/tls/notary.key".to_string(),
                certificate_pem_path: "./fixture/tls/notary.crt".to_string(),
            })
        } else {
            None
        },
        notary_signature: NotarySignatureProperties {
            private_key_pem_path: "./fixture/notary/notary.key".to_string(),
        },
        tracing: TracingProperties {
            default_level: "DEBUG".to_string(),
        },
    };

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

#[tokio::test]
async fn test_tcp_prover() {
    // Notary server configuration setup
    let notary_config = setup_config_and_server(100, 7048, true).await;

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

    let notary_host = notary_config.server.host.clone();
    let notary_port = notary_config.server.port;
    let notary_socket = tokio::net::TcpStream::connect(SocketAddr::new(
        IpAddr::V4(notary_host.parse().unwrap()),
        notary_port,
    ))
    .await
    .unwrap();

    let notary_tls_socket = notary_connector
        .connect(
            notary_config.server.name.as_str().try_into().unwrap(),
            notary_socket,
        )
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
        client_type: notary_server::ClientType::Tcp,
        max_transcript_size: Some(notary_config.notarization.max_transcript_size),
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

    debug!("Sending configuration request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent configuration request");

    assert!(response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
    let request = Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .uri(format!(
            "https://{}:{}/notarize?sessionId={}",
            notary_host,
            notary_port,
            notarization_response.session_id.clone()
        ))
        .method("GET")
        .header("Host", notary_host)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        .body(Body::empty())
        .unwrap();

    debug!("Sending notarization request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent notarization request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    debug!("Switched protocol OK");

    // Claim back the TCP socket after HTTP exchange is done so that client can use it for notarization
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

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
        .build()
        .unwrap();

    // Bind the Prover to the sockets
    let prover = Prover::new(prover_config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();
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

    builder.commit_sent(0..sent_len).unwrap();
    builder.commit_recv(0..recv_len).unwrap();

    _ = prover.finalize().await.unwrap();

    debug!("Done notarization!");
}

#[tokio::test]
async fn test_tls_less_tcp_prover() {
    // Notary server configuration setup
    let notary_config = setup_config_and_server(100, 7049, false).await;

    let notary_host = notary_config.server.host.clone();
    let notary_port = notary_config.server.port;
    let notary_socket = tokio::net::TcpStream::connect(SocketAddr::new(
        IpAddr::V4(notary_host.parse().unwrap()),
        notary_port,
    ))
    .await
    .unwrap();

    // Attach the hyper HTTP client to the notary connection to send request to the /session
    // endpoint to configure notarization and obtain session id
    let (mut request_sender, connection) =
        hyper::client::conn::handshake(notary_socket).await.unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: notary_server::ClientType::Tcp,
        max_transcript_size: Some(notary_config.notarization.max_transcript_size),
    })
    .unwrap();
    let request = Request::builder()
        .uri(format!("http://{notary_host}:{notary_port}/session"))
        .method("POST")
        .header("Host", notary_host.clone())
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    debug!("Sending configuration request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent configuration request");

    assert!(response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted
    // later
    let request = Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to
        // use as the configuration is set in the previous HTTP call
        .uri(format!(
            "http://{}:{}/notarize?sessionId={}",
            notary_host,
            notary_port,
            notarization_response.session_id.clone()
        ))
        .method("GET")
        .header("Host", notary_host)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        .body(Body::empty())
        .unwrap();

    debug!("Sending notarization request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent notarization request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    debug!("Switched protocol OK");

    // Claim back the TCP socket after HTTP exchange is done so that client can use it for
    // notarization
    let Parts {
        io: notary_socket, ..
    } = connection_task.await.unwrap().unwrap();

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
        .build()
        .unwrap();

    // Bind the Prover to the sockets
    let prover = Prover::new(prover_config)
        .setup(notary_socket.compat())
        .await
        .unwrap();
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

    builder.commit_sent(0..sent_len).unwrap();
    builder.commit_recv(0..recv_len).unwrap();

    _ = prover.finalize().await.unwrap();

    debug!("Done notarization!");
}

#[tokio::test]
async fn test_websocket_prover() {
    // Notary server configuration setup
    let notary_config = setup_config_and_server(100, 7050, true).await;
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
        max_transcript_size: Some(notary_config.notarization.max_transcript_size),
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

    builder.commit_sent(0..sent_len).unwrap();
    builder.commit_recv(0..recv_len).unwrap();

    _ = prover.finalize().await.unwrap();

    debug!("Done notarization!");
}
