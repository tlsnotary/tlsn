use std::{str, sync::Arc};

use core::future::Future;
use futures::{AsyncReadExt, AsyncWriteExt};
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rstest::{fixture, rstest};
use tls_client::{Certificate, ClientConfig, ClientConnection, RustCryptoBackend, ServerName};
use tls_client_async::{bind_client, ClosedConnection, ConnectionError, TlsConnection};
use tls_server_fixture::{
    bind_test_server, bind_test_server_hyper, APP_RECORD_LENGTH, CA_CERT_DER, CLOSE_DELAY,
    SERVER_DOMAIN,
};
use tokio::task::JoinHandle;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

// An established client TLS connection
struct TlsFixture {
    client_tls_conn: TlsConnection,
    // a handle that must be `.await`ed to get the result of a TLS connection
    closed_tls_task: JoinHandle<Result<ClosedConnection, ConnectionError>>,
}

// Sets up a TLS connection between client and server and sends a hello message
#[fixture]
async fn set_up_tls() -> TlsFixture {
    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);

    let _server_task = tokio::spawn(bind_test_server(server_socket.compat()));

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

    let (mut client_tls_conn, tls_fut) = bind_client(client_socket.compat(), client);

    let closed_tls_task = tokio::spawn(tls_fut);

    client_tls_conn
        .write_all(&pad("expecting you to send back hello".to_string()))
        .await
        .unwrap();

    // give the server some time to respond
    std::thread::sleep(std::time::Duration::from_millis(10));

    let mut plaintext = vec![0u8; 320];
    let n = client_tls_conn.read(&mut plaintext).await.unwrap();
    let s = str::from_utf8(&plaintext[0..n]).unwrap();

    assert_eq!(s, "hello");

    TlsFixture {
        client_tls_conn,
        closed_tls_task,
    }
}

// Expect the async tls client wrapped in `hyper::client` to make a successful
// request and receive the expected response
#[tokio::test]
async fn test_hyper_ok() {
    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);

    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

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
        hyper::client::conn::http1::handshake(TokioIo::new(conn.compat()))
            .await
            .unwrap();

    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{}/echo", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("POST")
        .body(Full::<Bytes>::new("hello".into()))
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    // Process the response body
    response.into_body().collect().await.unwrap().to_bytes();

    let _ = server_task.await.unwrap();

    let closed_conn = closed_tls_task.await.unwrap().unwrap();

    assert!(closed_conn.client.received_close_notify());
}

// Expect a clean TLS connection closure when server responds to the client's
// close_notify but doesn't close the socket
#[rstest]
#[tokio::test]
async fn test_ok_server_no_socket_close(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to send close_notify back to us after 10 ms
    client_tls_conn
        .write_all(&pad("send_close_notify".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // closing `client_tls_conn` will cause close_notify to be sent by the client;
    client_tls_conn.close().await.unwrap();

    let closed_conn = closed_tls_task.await.unwrap().unwrap();

    assert!(closed_conn.client.received_close_notify());
}

// Expect a clean TLS connection closure when server responds to the client's
// close_notify AND also closes the socket
#[rstest]
#[tokio::test]
async fn test_ok_server_socket_close(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to send close_notify back to us AND close the socket
    // after 10 ms
    client_tls_conn
        .write_all(&pad("send_close_notify_and_close_socket".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // closing `client_tls_conn` will cause close_notify to be sent by the client;
    client_tls_conn.close().await.unwrap();

    let closed_conn = closed_tls_task.await.unwrap().unwrap();

    assert!(closed_conn.client.received_close_notify());
}

// Expect a clean TLS connection closure when server sends close_notify first
// but doesn't close the socket
#[rstest]
#[tokio::test]
async fn test_ok_server_close_notify(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to send close_notify back to us after 10 ms
    client_tls_conn
        .write_all(&pad("send_close_notify".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // give enough time for server's close_notify to arrive
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    client_tls_conn.close().await.unwrap();

    let closed_conn = closed_tls_task.await.unwrap().unwrap();

    assert!(closed_conn.client.received_close_notify());
}

// Expect a clean TLS connection closure when server sends close_notify first
// AND also closes the socket
#[rstest]
#[tokio::test]
async fn test_ok_server_close_notify_and_socket_close(
    set_up_tls: impl Future<Output = TlsFixture>,
) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to send close_notify back to us after 10 ms
    client_tls_conn
        .write_all(&pad("send_close_notify_and_close_socket".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // give enough time for server's close_notify to arrive
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    client_tls_conn.close().await.unwrap();

    let closed_conn = closed_tls_task.await.unwrap().unwrap();

    assert!(closed_conn.client.received_close_notify());
}

// Expect to be able to read the data after server closes the socket abruptly
#[rstest]
#[tokio::test]
async fn test_ok_read_after_close(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        ..
    } = set_up_tls.await;

    // instruct the server to send us a hello message
    client_tls_conn
        .write_all(&pad("send a hello message".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // instruct the server to close the socket
    client_tls_conn
        .write_all(&pad("close_socket".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // give enough time to close the socket
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // try to read some more data
    let mut buf = vec![0u8; 10];
    let n = client_tls_conn.read(&mut buf).await.unwrap();

    assert_eq!(std::str::from_utf8(&buf[0..n]).unwrap(), "hello");
}

// Expect there to be no error when server DOES NOT send close_notify but just
// closes the socket
#[rstest]
#[tokio::test]
async fn test_ok_server_no_close_notify(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to close the socket
    client_tls_conn
        .write_all(&pad("close_socket".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // give enough time to close the socket
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    client_tls_conn.close().await.unwrap();

    let closed_conn = closed_tls_task.await.unwrap().unwrap();

    assert!(!closed_conn.client.received_close_notify());
}

// Expect to register a delay when the server delays closing the socket
#[rstest]
#[tokio::test]
async fn test_ok_delay_close(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    client_tls_conn
        .write_all(&pad("must_delay_when_closing".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // closing `client_tls_conn` will cause close_notify to be sent by the client
    client_tls_conn.close().await.unwrap();

    use std::time::Instant;
    let now = Instant::now();
    // this will resolve when the server stops delaying closing the socket
    let closed_conn = closed_tls_task.await.unwrap().unwrap();
    let elapsed = now.elapsed();

    // the elapsed time must be roughly equal to the server's delay
    // (give or take timing variations)
    assert!(elapsed.as_millis() as u64 > CLOSE_DELAY - 50);

    assert!(!closed_conn.client.received_close_notify());
}

// Expect client to error when server sends a corrupted message
#[rstest]
#[tokio::test]
async fn test_err_corrupted(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to send a corrupted message
    client_tls_conn
        .write_all(&pad("send_corrupted_message".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    client_tls_conn.close().await.unwrap();

    assert_eq!(
        closed_tls_task.await.unwrap().err().unwrap().to_string(),
        "received corrupt message"
    );
}

// Expect client to error when server sends a TLS record with a bad MAC
#[rstest]
#[tokio::test]
async fn test_err_bad_mac(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to send us a TLS record with a bad MAC
    client_tls_conn
        .write_all(&pad("send_record_with_bad_mac".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    client_tls_conn.close().await.unwrap();

    assert_eq!(
        closed_tls_task.await.unwrap().err().unwrap().to_string(),
        "backend error: Decryption error: \"aead::Error\""
    );
}

// Expect client to error when server sends a fatal alert
#[rstest]
#[tokio::test]
async fn test_err_alert(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        closed_tls_task,
    } = set_up_tls.await;

    // instruct the server to send us a TLS record with a bad MAC
    client_tls_conn
        .write_all(&pad("send_alert".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    client_tls_conn.close().await.unwrap();

    assert_eq!(
        closed_tls_task.await.unwrap().err().unwrap().to_string(),
        "received fatal alert: BadRecordMac"
    );
}

// Expect an error when trying to write data to a connection which server closed
// abruptly
#[rstest]
#[tokio::test]
async fn test_err_write_after_close(set_up_tls: impl Future<Output = TlsFixture>) {
    let TlsFixture {
        mut client_tls_conn,
        ..
    } = set_up_tls.await;

    // instruct the server to close the socket
    client_tls_conn
        .write_all(&pad("close_socket".to_string()))
        .await
        .unwrap();
    client_tls_conn.flush().await.unwrap();

    // give enough time to close the socket
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // try to send some more data
    let res = client_tls_conn
        .write_all(&pad("more data".to_string()))
        .await;

    assert_eq!(res.err().unwrap().kind(), std::io::ErrorKind::BrokenPipe);
}

// Converts a string into a slice zero-padded to APP_RECORD_LENGTH
fn pad(s: String) -> Vec<u8> {
    assert!(s.len() <= APP_RECORD_LENGTH);
    let mut buf = vec![0u8; APP_RECORD_LENGTH];
    buf[..s.len()].copy_from_slice(s.as_bytes());
    buf
}
