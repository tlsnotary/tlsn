use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    hash::HashAlgId,
    prover::Prover,
    transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitmentKind},
    verifier::{Verifier, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_core::ProverOutput;
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use tokio_util::compat::TokioAsyncReadCompatExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test() {
    tracing_subscriber::fmt::init();

    // Session channel for prover <-> verifier protocol communication.
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(socket_0.compat());
    let mut session_v = Session::new(socket_1.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .proxy()
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    // Proxy channels: prover <-> verifier <-> server
    let (prover_proxy, verifier_prover_end) = tokio::io::duplex(2 << 16);
    let (verifier_server_end, server_proxy) = tokio::io::duplex(2 << 16);

    // Spawn the TLS server on the far end of the proxy chain.
    let server_task = tokio::spawn(bind(server_proxy.compat()));

    let ((_full_transcript, _prover_output), verifier_output) = tokio::join!(
        run_prover(prover, prover_proxy),
        run_verifier(verifier, verifier_prover_end, verifier_server_end)
    );

    let _ = server_task.await.unwrap();

    session_p_handle.close();
    session_v_handle.close();

    let partial_transcript = verifier_output.transcript.unwrap();
    let ServerName::Dns(server_name) = verifier_output.server_name.unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript.sent_authed().iter().next().unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript.received_authed().iter().next().unwrap(),
        0..10
    );
}

async fn run_prover(
    prover: Prover,
    proxy_socket: tokio::io::DuplexStream,
) -> (Transcript, ProverOutput) {
    let prover = prover
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    ProxyTlsConfig::builder()
                        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    // In proxy mode the prover connects through the verifier's proxy.
    let (mut tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
            proxy_socket.compat(),
        )
        .unwrap();
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    // TODO: check if there is no better way.
    tls_connection.close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap();
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

async fn run_verifier(
    verifier: Verifier,
    prover_socket: tokio::io::DuplexStream,
    server_socket: tokio::io::DuplexStream,
) -> VerifierOutput {
    let mut verifier = verifier.commit().await.unwrap().accept().await.unwrap();

    verifier.set_proxy_sockets(prover_socket.compat(), server_socket.compat());

    let verifier = verifier.run().await.unwrap();

    let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
    verifier.close().await.unwrap();

    output
}
