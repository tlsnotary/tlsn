use std::future::IntoFuture;

use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn::{
    config::{
        prove::ProveConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    },
    connection::ServerName,
    hash::HashAlgId,
    prover::Prover,
    transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitmentKind},
    verifier::{Verifier, VerifierCommitAccepted},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_core::{ProverOutput, VerifierOutput};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;

pub async fn run_prover_mpc(
    config: TlsCommitConfig<MpcTlsConfig>,
    prover: Prover,
    server_socket: Option<tokio::io::DuplexStream>,
) -> Prover<tlsn::prover::state::Committed> {
    let prover = prover.commit(config).await.unwrap();

    let socket = server_socket.expect("connection to server should be provided");
    let (mut tls_connection, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
            socket.compat(),
        )
        .unwrap();
    let prover_task = tokio::spawn(prover.into_future());

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    prover_task.await.unwrap().unwrap()
}

pub async fn run_prover_proxy(
    config: TlsCommitConfig<ProxyTlsConfig>,
    prover: Prover,
) -> Prover<tlsn::prover::state::Committed> {
    let prover = prover.commit(config).await.unwrap();

    let (mut tls_connection, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();
    let prover_task = tokio::spawn(prover.into_future());

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    tls_connection.close().await.unwrap();

    prover_task.await.unwrap().unwrap()
}

pub async fn finish_prover(
    mut prover: Prover<tlsn::prover::state::Committed>,
) -> (Transcript, ProverOutput) {
    let sent_tx_len = prover.transcript().sent().len();
    let recv_tx_len = prover.transcript().received().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    let kind = TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    };
    builder
        .commit_with_kind(&(0..sent_tx_len), Direction::Sent, kind)
        .unwrap();
    builder
        .commit_with_kind(&(0..recv_tx_len), Direction::Received, kind)
        .unwrap();
    builder
        .commit_with_kind(&(1..sent_tx_len - 1), Direction::Sent, kind)
        .unwrap();
    builder
        .commit_with_kind(&(1..recv_tx_len - 1), Direction::Received, kind)
        .unwrap();

    let transcript_commit = builder.build().unwrap();

    let mut builder = ProveConfig::builder(prover.transcript());

    builder.server_identity();

    builder.reveal_sent(&(0..10)).unwrap();
    builder.reveal_recv(&(0..10)).unwrap();

    builder.transcript_commit(transcript_commit);

    let config = builder.build().unwrap();
    let transcript = prover.transcript().clone();
    let output = prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();

    (transcript, output)
}

pub async fn run_verifier(
    verifier: Verifier,
    server_socket: Option<tokio::io::DuplexStream>,
) -> VerifierOutput {
    let verifier = verifier.commit().await.unwrap();

    let verifier = match verifier.accept().await.unwrap() {
        VerifierCommitAccepted::Mpc(verifier) => verifier.run().await.unwrap(),
        VerifierCommitAccepted::Proxy(verifier) => {
            let socket = server_socket.unwrap();
            verifier.run(socket.compat()).await.unwrap()
        }
    };

    let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
    verifier.close().await.unwrap();

    output
}
