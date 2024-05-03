use http_body_util::{BodyExt as _, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn_core::{proof::SessionInfo, Direction, RedactedTranscript};
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

    let (socket_0, socket_1) = tokio::io::duplex(1 << 23);

    let (_, (sent, received, _session_info)) = tokio::join!(prover(socket_0), verifier(socket_1));

    assert_eq!(sent.authed(), &RangeSet::from(0..sent.data().len() - 1));
    assert_eq!(
        sent.redacted(),
        &RangeSet::from(sent.data().len() - 1..sent.data().len())
    );

    assert_eq!(received.authed(), &RangeSet::from(2..received.data().len()));
    assert_eq!(received.redacted(), &RangeSet::from(0..2));
}

#[instrument(skip(notary_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);

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

    let sent_transcript_len = prover.sent_transcript().data().len();
    let recv_transcript_len = prover.recv_transcript().data().len();

    // Reveal parts of the transcript
    _ = prover.reveal(0..sent_transcript_len - 1, Direction::Sent);
    _ = prover.reveal(2..recv_transcript_len, Direction::Received);
    prover.prove().await.unwrap();

    prover.finalize().await.unwrap()
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> (RedactedTranscript, RedactedTranscript, SessionInfo) {
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

    let (sent, received, session_info) = verifier.verify(socket.compat()).await.unwrap();
    (sent, received, session_info)
}
