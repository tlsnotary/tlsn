use http_body_util::{BodyExt as _, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tls_core::verify::WebPkiVerifier;
use tlsn_core::{
    attestation::AttestationConfig, request::RequestConfig, signing::SignatureAlgId,
    transcript::TranscriptCommitConfig, CryptoProvider,
};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

#[tokio::test]
#[ignore]
async fn notarize() {
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
        .uri(format!("https://{}/bytes?size=16000", SERVER_DOMAIN))
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

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();
    let sent_tx_len = prover.transcript().sent().len();
    let recv_tx_len = prover.transcript().received().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // Commit to everything
    builder.commit_sent(&(0..sent_tx_len)).unwrap();
    builder.commit_recv(&(0..recv_tx_len)).unwrap();

    let config = builder.build().unwrap();

    prover.transcript_commit(config);

    let config = RequestConfig::default();

    prover
        .finalize_with_provider(&config, &CryptoProvider::default())
        .await
        .unwrap();
}

#[instrument(skip(socket))]
async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let mut provider = CryptoProvider::default();
    provider.cert = WebPkiVerifier::new(root_store, None);

    provider.signer.set_secp256k1(&[1u8; 32]).unwrap();

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .id("test")
            .crypto_provider(provider)
            .build()
            .unwrap(),
    );

    let config = AttestationConfig::builder()
        .supported_signature_algs(vec![SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    _ = verifier.notarize(socket.compat(), &config).await.unwrap();
}
