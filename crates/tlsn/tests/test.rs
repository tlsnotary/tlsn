use futures::{AsyncReadExt, AsyncWriteExt};
use tls_core::verify::WebPkiVerifier;
use tlsn::{
    config::{ProtocolConfig, ProtocolConfigValidator},
    prover::{Prover, ProverConfig},
    transcript::TranscriptCommitConfig,
    verifier::{Verifier, VerifierConfig},
};
use tlsn_attestation::{
    AttestationConfig, CryptoProvider, request::RequestConfig, signing::SignatureAlgId,
};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::instrument;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of application records sent from prover to server
const MAX_SENT_RECORDS: usize = 4;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;
// Maximum number of application records received by prover from server
const MAX_RECV_RECORDS: usize = 6;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test() {
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    tokio::join!(prover(socket_0), verifier(socket_1));
}

#[instrument(skip(verifier_socket))]
#[allow(deprecated)]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(verifier_socket: T) {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(bind(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(SERVER_DOMAIN)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(MAX_SENT_DATA)
                    .max_sent_records(MAX_SENT_RECORDS)
                    .max_recv_data(MAX_RECV_DATA)
                    .max_recv_records_online(MAX_RECV_RECORDS)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    let (mut tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    let _ = server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap();
    let sent_tx_len = prover.transcript().sent().len();
    let recv_tx_len = prover.transcript().received().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // Commit to everything
    builder.commit_sent(&(0..sent_tx_len)).unwrap();
    builder.commit_recv(&(0..recv_tx_len)).unwrap();

    let transcript_commit = builder.build().unwrap();

    let mut builder = RequestConfig::builder();

    builder.transcript_commit(transcript_commit);

    let config = builder.build().unwrap();

    prover
        .notarize_with_provider(&config, &CryptoProvider::default())
        .await
        .unwrap();
    prover.close().await.unwrap();
}

#[instrument(skip(socket))]
#[allow(deprecated)]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let mut provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    provider.signer.set_secp256k1(&[1u8; 32]).unwrap();

    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .protocol_config_validator(config_validator)
            .build()
            .unwrap(),
    );

    let config = AttestationConfig::builder()
        .supported_signature_algs(vec![SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    _ = verifier
        .notarize_with_provider(socket.compat(), &config, &CryptoProvider::default())
        .await
        .unwrap();
}
