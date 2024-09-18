use std::{env, net::IpAddr};

use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt, Future};
use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::{
    attestation::AttestationConfig, signing::SignatureAlgId, transcript::Idx, CryptoProvider,
};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, instrument};

use crate::{
    DEFAULT_NOTARY_PORT, DEFAULT_PROVER_PORT, DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT,
    DEFAULT_VERIFIER_PORT,
};

#[instrument]
pub async fn start() -> Result<impl Future<Output = Result<()>>> {
    let verifier_port: u16 = env::var("VERIFIER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_VERIFIER_PORT);
    let notary_port: u16 = env::var("NOTARY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_NOTARY_PORT);
    let prover_port: u16 = env::var("PROVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_PROVER_PORT);
    let addr: IpAddr = env::var("TLSN_IP")
        .map(|addr| addr.parse().expect("should be valid IP address"))
        .unwrap_or(IpAddr::V4(DEFAULT_SERVER_IP.parse().unwrap()));

    let verifier_listener = TcpListener::bind((addr, verifier_port)).await?;
    let notary_listener = TcpListener::bind((addr, notary_port)).await?;
    let prover_listener = TcpListener::bind((addr, prover_port)).await?;

    Ok(async move {
        loop {
            tokio::select! {
                res = verifier_listener.accept() => {
                    let (socket, addr) = res?;
                    info!("verifier accepted connection from: {}", addr);

                    tokio::spawn(handle_verifier(socket));
                },
                res = notary_listener.accept() => {
                    let (socket, addr) = res?;
                    info!("notary accepted connection from: {}", addr);

                    tokio::spawn(handle_notary(socket));
                },
                res = prover_listener.accept() => {
                    let (socket, addr) = res?;
                    info!("prover accepted connection from: {}", addr);

                    tokio::spawn(handle_prover(socket));
                },
            }
        }
    })
}

#[instrument(level = "debug", skip_all, err)]
async fn handle_verifier(io: TcpStream) -> Result<()> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(1024)
        .max_recv_data(1024)
        .build()
        .unwrap();

    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let config = VerifierConfig::builder()
        .crypto_provider(provider)
        .protocol_config_validator(config_validator)
        .build()
        .unwrap();

    let verifier = Verifier::new(config);

    verifier.verify(io.compat()).await?;

    Ok(())
}

#[instrument(level = "debug", skip_all, err)]
async fn handle_notary(io: TcpStream) -> Result<()> {
    let mut provider = CryptoProvider::default();

    provider.signer.set_secp256k1(&[1u8; 32]).unwrap();

    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(1024)
        .max_recv_data(1024)
        .build()
        .unwrap();

    let config = VerifierConfig::builder()
        .protocol_config_validator(config_validator)
        .crypto_provider(provider)
        .build()
        .unwrap();

    let verifier = Verifier::new(config);

    let mut builder = AttestationConfig::builder();
    builder.supported_signature_algs(vec![SignatureAlgId::SECP256K1]);

    let attestation_config = builder.build().unwrap();

    verifier.notarize(io.compat(), &attestation_config).await?;

    Ok(())
}

#[instrument(level = "debug", skip_all, err)]
async fn handle_prover(io: TcpStream) -> Result<()> {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let protocol_config = ProtocolConfig::builder()
        .max_sent_data(1024)
        .max_recv_data(1024)
        .build()
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(SERVER_DOMAIN)
            .protocol_config(protocol_config)
            .crypto_provider(provider)
            .build()
            .unwrap(),
    )
    .setup(io.compat())
    .await
    .unwrap();

    let port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_SERVER_PORT);
    let addr: IpAddr = env::var("SERVER_IP")
        .map(|addr| addr.parse().expect("should be valid IP address"))
        .unwrap_or(IpAddr::V4(DEFAULT_SERVER_IP.parse().unwrap()));

    let client_socket = TcpStream::connect((addr, port)).await.unwrap();

    let (mut tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_prove();

    let sent_transcript_len = prover.transcript().sent().len();
    let recv_transcript_len = prover.transcript().received().len();

    let sent_idx = Idx::new(0..sent_transcript_len - 1);
    let recv_idx = Idx::new(2..recv_transcript_len);

    // Reveal parts of the transcript
    prover.prove_transcript(sent_idx, recv_idx).await.unwrap();

    prover.finalize().await.unwrap();

    Ok(())
}
