use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::instrument;

#[tokio::test]
#[ignore]
async fn test_defer_decryption() {
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    tokio::join!(prover(socket_0), notary(socket_1));
}

#[instrument(skip(notary_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(tlsn_server_fixture::bind(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
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

    let (mut tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let prover_ctrl = prover_fut.control();
    let prover_task = tokio::spawn(prover_fut);

    // Defer decryption until after the server closes the connection.
    prover_ctrl.defer_decryption().await.unwrap();

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    let _ = server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();
    let sent_tx_len = prover.sent_transcript().data().len();
    let recv_tx_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    // Commit to everything
    builder.commit_sent(&(0..sent_tx_len)).unwrap();
    builder.commit_recv(&(0..recv_tx_len)).unwrap();

    let _notarized_session = prover.finalize().await.unwrap();
}

#[instrument(skip(socket))]
async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let verifier = Verifier::new(VerifierConfig::builder().id("test").build().unwrap());
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    _ = verifier
        .notarize::<_, p256::ecdsa::Signature>(socket.compat(), &signing_key)
        .await
        .unwrap();
}
