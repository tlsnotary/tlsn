use futures::AsyncWriteExt;
use hyper::{body::to_bytes, Body, Request, StatusCode};
use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn_core::{conn::ServerIdentity, PartialTranscript};
use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;
use utils::range::RangeSet;

#[tokio::test]
#[ignore]
async fn verify() {
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    let (_, (partial_transcript, server_identity)) =
        tokio::join!(prover(socket_0), verifier(socket_1));

    assert_eq!(
        partial_transcript.sent_authed(),
        &RangeSet::from(0..partial_transcript.sent_unsafe().len() - 1)
    );
    assert_eq!(
        partial_transcript.sent_unauthed(),
        RangeSet::from(
            partial_transcript.sent_unsafe().len() - 1..partial_transcript.sent_unsafe().len()
        )
    );

    assert_eq!(
        partial_transcript.received_authed(),
        &RangeSet::from(2..partial_transcript.received_unsafe().len())
    );
    assert_eq!(partial_transcript.received_unauthed(), RangeSet::from(0..2));

    assert_eq!(
        server_identity,
        ServerIdentity::new(SERVER_DOMAIN.to_string())
    );
}

#[instrument(skip(notary_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(tlsn_server_fixture::bind(server_socket.compat()));

    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store)
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
        .uri(format!("https://{}", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    println!(
        "{:?}",
        String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
    );

    server_task.await.unwrap();

    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

    client_socket.close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_prove();

    let (sent_len, recv_len) = prover.transcript().len();

    let builder = prover.substring_proof_builder();

    // Reveal parts of the transcript
    _ = builder.reveal_sent(&(0..sent_len - 1)).unwrap();
    _ = builder.reveal_recv(&(2..recv_len)).unwrap();

    prover.prove().await.unwrap();

    prover.finalize().await.unwrap()
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> (PartialTranscript, ServerIdentity) {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let verifier_config = VerifierConfig::builder()
        .id("test")
        .cert_verifier(WebPkiVerifier::new(root_store, None))
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    verifier.verify(socket.compat()).await.unwrap()
}
