use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn::{
    config::{ProtocolConfig, ProtocolConfigValidator},
    prover::{Prover, ProverConfig},
    verifier::{Verifier, VerifierConfig},
};
use tlsn_core::{
    CryptoProvider, ProveConfig, VerifierOutput, VerifyConfig,
    hash::HashAlgId,
    transcript::{TranscriptCommitConfig, TranscriptCommitment, TranscriptCommitmentKind},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, StatusCode, body::Bytes};

use crate::{IoProvider, io::FuturesIo, spawn};

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 11;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 11;

crate::test!("basic", prover, verifier);

async fn prover(provider: &IoProvider) {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(SERVER_DOMAIN)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(MAX_SENT_DATA)
                    .max_recv_data(MAX_RECV_DATA)
                    .defer_decryption_from_start(true)
                    .build()
                    .unwrap(),
            )
            .crypto_provider(crypto_provider)
            .build()
            .unwrap(),
    )
    .setup(provider.provide_proto_io().await.unwrap())
    .await
    .unwrap();

    let (tls_connection, prover_fut) = prover
        .connect(provider.provide_server_io().await.unwrap())
        .await
        .unwrap();

    let prover_task = spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(FuturesIo::new(tls_connection))
            .await
            .unwrap();

    _ = spawn(connection);

    let request = Request::builder()
        .uri(format!(
            "https://{}/bytes?size={recv}",
            SERVER_DOMAIN,
            recv = MAX_RECV_DATA - 256
        ))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let _ = response.into_body().collect().await.unwrap().to_bytes();

    let mut prover = prover_task.await.unwrap().unwrap();

    let (sent_len, recv_len) = prover.transcript().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });

    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    let transcript_commit = builder.build().unwrap();

    let mut builder = ProveConfig::builder(prover.transcript());

    builder
        .server_identity()
        .reveal_sent(&(0..sent_len - 1))
        .unwrap()
        .reveal_recv(&(2..recv_len))
        .unwrap()
        .transcript_commit(transcript_commit);

    let config = builder.build().unwrap();

    prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();
}

async fn verifier(provider: &IoProvider) {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let crypto_provider = CryptoProvider {
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
        .crypto_provider(crypto_provider)
        .build()
        .unwrap();

    let verifier = Verifier::new(config);

    let VerifierOutput {
        server_name,
        transcript_commitments,
        ..
    } = verifier
        .verify(
            provider.provide_proto_io().await.unwrap(),
            &VerifyConfig::default(),
        )
        .await
        .unwrap();

    assert_eq!(server_name.unwrap().as_str(), SERVER_DOMAIN);
    assert!(
        transcript_commitments
            .iter()
            .any(|commitment| matches!(commitment, TranscriptCommitment::Hash { .. }))
    );
}
