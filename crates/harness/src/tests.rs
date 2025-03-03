use futures::{AsyncReadExt, AsyncWriteExt};
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::{transcript::Idx, CryptoProvider};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::{Verifier, VerifierConfig};

use crate::{test::test, ProverProvider, VerifierProvider};

async fn test_prover(provider: &mut ProverProvider) {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let mut builder = ProtocolConfig::builder();
    builder
        .max_sent_data(4096)
        .max_recv_data_online(4096)
        .max_recv_data(4096);

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(SERVER_DOMAIN)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(4096)
                    .max_recv_data(4096)
                    .build()
                    .unwrap(),
            )
            .crypto_provider(crypto_provider)
            .build()
            .unwrap(),
    );

    let prover = prover
        .setup(provider.provide_verifier().await.unwrap())
        .await
        .unwrap();

    let (mut conn, fut) = prover
        .connect(provider.provide_server().await.unwrap())
        .await
        .unwrap();

    let (_, prover) = futures::join!(
        async {
            conn.write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            conn.close().await.unwrap();

            let mut response = vec![0u8; 1024];
            conn.read_to_end(&mut response).await.unwrap();
        },
        async { fut.await.unwrap() }
    );

    let mut prover = prover.start_prove();

    let (sent_len, recv_len) = prover.transcript().len();

    prover
        .prove_transcript(Idx::new(0..sent_len), Idx::new(0..recv_len))
        .await
        .unwrap();

    prover.finalize().await.unwrap();
}

async fn test_verifier(provider: &mut VerifierProvider) {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(4096)
        .max_recv_data(4096)
        .build()
        .unwrap();

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .protocol_config_validator(config_validator)
            .crypto_provider(crypto_provider)
            .build()
            .unwrap(),
    );

    let _ = verifier
        .verify(provider.provide_prover().await.unwrap())
        .await
        .unwrap();
}

test!("test_basic", test_prover, test_verifier);
