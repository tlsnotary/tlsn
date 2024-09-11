use http_body_util::{BodyExt as _, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn_core::{
    transcript::{Idx, PartialTranscript},
    CryptoProvider,
};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::{SessionInfo, Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

#[tokio::test]
#[ignore]
async fn verify() {
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(1 << 23);

    let (_, (partial_transcript, info)) = tokio::join!(prover(socket_0), verifier(socket_1));

    assert_eq!(
        partial_transcript.sent_authed(),
        &Idx::new(0..partial_transcript.len_sent() - 1)
    );
    assert_eq!(
        partial_transcript.received_authed(),
        &Idx::new(2..partial_transcript.len_received())
    );
    assert_eq!(info.server_name.as_str(), SERVER_DOMAIN);
}

#[instrument(skip(notary_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);

    let server_task = tokio::spawn(tlsn_server_fixture::bind(server_socket.compat()));

    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let mut provider = CryptoProvider::default();
    provider.cert = WebPkiVerifier::new(root_store, None);

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_name(SERVER_DOMAIN)
            .crypto_provider(provider)
            .build()
            .unwrap(),
    )
    .setup(notary_socket.compat())
    .await
    .unwrap();

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{}", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let payload = response.into_body().collect().await.unwrap().to_bytes();
    println!("{:?}", &String::from_utf8_lossy(&payload));

    let _ = server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_prove();

    let (sent_len, recv_len) = prover.transcript().len();

    let idx_sent = Idx::new(0..sent_len - 1);
    let idx_recv = Idx::new(2..recv_len);

    // Reveal parts of the transcript
    prover.prove_transcript(idx_sent, idx_recv).await.unwrap();
    prover.finalize().await.unwrap();
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> (PartialTranscript, SessionInfo) {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let mut provider = CryptoProvider::default();

    provider.cert = WebPkiVerifier::new(root_store, None);

    let verifier_config = VerifierConfig::builder()
        .id("test")
        .crypto_provider(provider)
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    verifier.verify(socket.compat()).await.unwrap()
}
