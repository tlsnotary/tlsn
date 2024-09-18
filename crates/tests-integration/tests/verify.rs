use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::{
    transcript::{Idx, PartialTranscript},
    CryptoProvider,
};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::{SessionInfo, Verifier, VerifierConfig};

use http_body_util::{BodyExt as _, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;

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

    let server_task = tokio::spawn(bind(server_socket.compat()));

    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(SERVER_DOMAIN)
            .defer_decryption_from_start(false)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(MAX_SENT_DATA)
                    .max_recv_data(MAX_RECV_DATA)
                    .max_recv_data_online(MAX_RECV_DATA)
                    .build()
                    .unwrap(),
            )
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

    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let config = VerifierConfig::builder()
        .protocol_config_validator(
            ProtocolConfigValidator::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()
                .unwrap(),
        )
        .crypto_provider(provider)
        .build()
        .unwrap();

    let verifier = Verifier::new(config);

    verifier.verify(socket.compat()).await.unwrap()
}
