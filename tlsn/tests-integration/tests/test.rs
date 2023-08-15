use futures::AsyncWriteExt;
use hyper::{body::to_bytes, Body, Request, StatusCode};
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tlsn_notary::{bind_notary, NotaryConfig};
use tlsn_prover::{bind_prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

#[tokio::test]
#[ignore]
async fn test() {
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    tokio::join!(prover(socket_0), notary(socket_1));
}

#[instrument(skip(notary_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let (tls_connection, prover_fut, mux_fut) = bind_prover(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store)
            .build()
            .unwrap(),
        client_socket.compat(),
        notary_socket.compat(),
    )
    .await
    .unwrap();

    tokio::spawn(mux_fut);
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

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    println!(
        "{:?}",
        String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
    );

    let mut server_tls_conn = server_task.await.unwrap().unwrap();

    // Make sure the server closes cleanly (sends close notify)
    server_tls_conn.close().await.unwrap();

    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

    client_socket.close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap();

    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    prover.add_commitment_sent(0..sent_len as u32).unwrap();
    prover.add_commitment_recv(0..recv_len as u32).unwrap();

    _ = prover.finalize().await.unwrap();
}

#[instrument(skip(socket))]
async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let (notary, notary_fut) = bind_notary(
        NotaryConfig::builder().id("test").build().unwrap(),
        socket.compat(),
    )
    .unwrap();

    tokio::spawn(notary_fut);

    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    notary
        .notarize::<p256::ecdsa::Signature>(&signing_key)
        .await
        .unwrap();
}
