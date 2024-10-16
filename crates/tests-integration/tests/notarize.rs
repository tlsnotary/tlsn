use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::{
    attestation::AttestationConfig, request::RequestConfig, signing::SignatureAlgId,
    transcript::TranscriptCommitConfig, CryptoProvider,
};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::{Verifier, VerifierConfig};

use http_body_util::{BodyExt as _, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

#[cfg(feature = "authdecode_unsafe")]
use tlsn_core::hash::HashAlgId;
#[cfg(feature = "authdecode_unsafe")]
use tlsn_core::hash::POSEIDON_MAX_INPUT_SIZE;
#[cfg(feature = "authdecode_unsafe")]
use tlsn_core::transcript::TranscriptCommitmentKind;

// Maximum number of bytes that can be sent from prover to server.
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server.
const MAX_RECV_DATA: usize = 1 << 14;
#[cfg(feature = "authdecode_unsafe")]
// Maximum number of bytes for which a zk-friendly hash commitment can be computed.
const MAX_ZK_FRIENDLY_HASH_DATA: usize = 1 << 10;

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

    let server_task = tokio::spawn(bind(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let mut builder = ProtocolConfig::builder();
    builder
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_data_online(MAX_RECV_DATA);

    #[cfg(feature = "authdecode_unsafe")]
    builder.max_zk_friendly_hash_data(MAX_ZK_FRIENDLY_HASH_DATA);

    let protocol_config = builder.build().unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(SERVER_DOMAIN)
            .defer_decryption_from_start(false)
            .protocol_config(protocol_config)
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

    // Commit to a portion of the data.
    builder
        .commit_sent(&(sent_tx_len / 2..sent_tx_len))
        .unwrap();
    builder
        .commit_recv(&(recv_tx_len / 2..recv_tx_len))
        .unwrap();

    #[cfg(feature = "authdecode_unsafe")]
    {
        builder.default_kind(TranscriptCommitmentKind::Hash {
            alg: HashAlgId::POSEIDON_HALO2,
        });
        // Currently there is a limit on commitment data length for POSEIDON_HALO2.
        let sent_range = 0..sent_tx_len / 2;
        let recv_range = 0..POSEIDON_MAX_INPUT_SIZE;
        assert!(sent_range.len() <= POSEIDON_MAX_INPUT_SIZE);
        assert!(recv_range.len() <= POSEIDON_MAX_INPUT_SIZE);
        builder
            .commit_sent(&sent_range)
            .unwrap()
            .commit_recv(&recv_range)
            .unwrap();
    }

    let config = builder.build().unwrap();

    prover.transcript_commit(config);

    let config = RequestConfig::default();

    prover.finalize(&config).await.unwrap();
}

#[instrument(skip(socket))]
async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let mut provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    provider.signer.set_secp256k1(&[1u8; 32]).unwrap();

    let mut builder = ProtocolConfigValidator::builder();
    builder
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA);

    #[cfg(feature = "authdecode_unsafe")]
    builder.max_zk_friendly_hash_data(MAX_ZK_FRIENDLY_HASH_DATA);

    let config_validator = builder.build().unwrap();

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .protocol_config_validator(config_validator)
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
