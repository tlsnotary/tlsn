use std::sync::Arc;

use futures::AsyncWriteExt;
use hyper::{body::to_bytes, Body, Request, StatusCode};
use tls_client::{Certificate, ClientConfig, ClientConnection, RustCryptoBackend, ServerName};
use tls_client_async::bind_client;
use tls_server_fixture::{bind_test_server, CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[tokio::test]
async fn test_async_client() {
    tracing_subscriber::fmt::init();

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(bind_test_server(server_socket.compat()));

    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add(&Certificate(CA_CERT_DER.to_vec())).unwrap();
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let client = ClientConnection::new(
        Arc::new(config),
        Box::new(RustCryptoBackend::new()),
        ServerName::try_from(SERVER_DOMAIN).unwrap(),
    )
    .unwrap();

    let (conn, tls_fut) = bind_client(client_socket.compat(), client);

    let closed_tls_task = tokio::spawn(tls_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::handshake(conn.compat()).await.unwrap();

    let http_task = tokio::spawn(connection.without_shutdown());

    let request = Request::builder()
        .uri(format!("https://{}/echo", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("POST")
        .body(Body::from("hello"))
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    // Process the response body
    to_bytes(response.into_body()).await.unwrap();

    let mut server_tls_conn = server_task.await.unwrap().unwrap();

    // Make sure the server closes cleanly (sends close notify)
    server_tls_conn.close().await.unwrap();

    let http_parts = http_task.await.unwrap().unwrap();
    let mut tls_conn = http_parts.io.into_inner();

    tls_conn.close().await.unwrap();

    let closed_conn = closed_tls_task.await.unwrap().unwrap();

    assert!(closed_conn.client.received_close_notify());
}
