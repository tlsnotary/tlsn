use std::{env, net::IpAddr};

use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt, Future};
use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn_core::Direction;
use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
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
        .add(&tls_core::key::Certificate(
            tlsn_server_fixture::CA_CERT_DER.to_vec(),
        ))
        .unwrap();

    let config = VerifierConfig::builder()
        .id("test")
        .max_sent_data(1024)
        .max_recv_data_online(1024)
        .cert_verifier(WebPkiVerifier::new(root_store, None))
        .build()
        .unwrap();

    let verifier = Verifier::new(config);

    verifier.verify(io.compat()).await?;

    Ok(())
}

#[instrument(level = "debug", skip_all, err)]
async fn handle_notary(io: TcpStream) -> Result<()> {
    let config = VerifierConfig::builder()
        .id("test")
        .max_sent_data(1024)
        .max_recv_data_online(1024)
        .build()
        .unwrap();

    let verifier = Verifier::new(config);
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());

    verifier
        .notarize::<_, p256::ecdsa::Signature>(io.compat(), &signing_key)
        .await?;

    Ok(())
}

#[instrument(level = "debug", skip_all, err)]
async fn handle_prover(io: TcpStream) -> Result<()> {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .max_sent_data(1024)
            .max_recv_data_online(1024)
            .root_cert_store(root_store)
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

    let mut prover = prover_task.await.unwrap().unwrap().start_prove();

    let sent_transcript_len = prover.sent_transcript().data().len();
    let recv_transcript_len = prover.recv_transcript().data().len();

    // Reveal parts of the transcript
    _ = prover.reveal(0..sent_transcript_len - 1, Direction::Sent);
    _ = prover.reveal(2..recv_transcript_len, Direction::Received);
    prover.prove().await.unwrap();

    prover.finalize().await.unwrap();

    Ok(())
}
