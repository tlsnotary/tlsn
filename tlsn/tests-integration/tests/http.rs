use std::io::Write;

use futures::AsyncWriteExt;
use hyper::{body::to_bytes, Body, Request, StatusCode};

use tlsn_core::proof::TlsProof;
use tlsn_notary::{bind_notary, NotaryConfig};
use tlsn_prover::tls::{Prover, ProverConfig};
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
    let client_socket = tokio::net::TcpStream::connect("httpbin.org:443")
        .await
        .unwrap();

    println!("opened");

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns("httpbin.org")
            .build()
            .unwrap(),
    )
    .setup(notary_socket.compat())
    .await
    .unwrap();

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
        .await
        .unwrap();

    let connection_task = tokio::spawn(connection.without_shutdown());

    let request = Request::builder()
        .uri("https://httpbin.org/json")
        .header("Host", "httpbin.org")
        .header("Connection", "keep-alive")
        .header("Accept", "application/json")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    println!(
        "{:?}",
        String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
    );

    let request = Request::builder()
        .uri("https://httpbin.org/html")
        .header("Host", "httpbin.org")
        .header("Connection", "close")
        .header("Accept", "text/html")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    println!(
        "{:?}",
        String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
    );

    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

    client_socket.close().await.unwrap();

    let mut prover = prover_task
        .await
        .unwrap()
        .unwrap()
        .to_http()
        .unwrap()
        .start_notarize();

    prover.commit().unwrap();

    let session = prover.finalize().await.unwrap();

    let mut file = std::fs::File::create("notarized_session.json").unwrap();
    file.write_all(bincode::serialize(&session).unwrap().as_slice())
        .unwrap();

    let proof = TlsProof {
        session: session.session_proof(),
        substrings: session.proof_builder().build().unwrap(),
    };

    let mut file = std::fs::File::create("proof.json").unwrap();
    file.write_all(serde_json::to_string(&proof).unwrap().as_bytes())
        .unwrap();
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
