use tls_server_fixture::SERVER_DOMAIN;
use tlsn::{
    Session,
    config::{
        prover::ProverConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::CA_CERT_DER;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, warn};

mod utils;
use utils::{finish_prover, run_prover_mpc, run_prover_proxy, run_verifier};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_mpc() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    // Maximum number of bytes that can be sent from prover to server
    const MAX_SENT_DATA: usize = 1 << 12;
    // Maximum number of application records sent from prover to server
    const MAX_SENT_RECORDS: usize = 4;
    // Maximum number of bytes that can be received by prover from server
    const MAX_RECV_DATA: usize = 1 << 14;
    // Maximum number of application records received by prover from server
    const MAX_RECV_RECORDS: usize = 6;

    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover_fut = async {
        let prover = run_prover_mpc(config, prover, Some(client_socket)).await;
        finish_prover(prover).await
    };

    let ((_full_transcript, _prover_output), verifier_output) =
        tokio::join!(prover_fut, run_verifier(verifier, None));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_proxy() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    let config = ProxyTlsConfig::builder()
        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover_fut = async {
        let prover = run_prover_proxy(config, prover).await;
        finish_prover(prover).await
    };

    let ((_full_transcript, _prover_output), verifier_output) =
        tokio::join!(prover_fut, run_verifier(verifier, Some(client_socket)));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();
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

/// A proxy target that accepts TCP but closes during ClientHello must fail,
/// rather than keep the TLS state machine pending with its server side closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_target_eof_during_handshake() {
    use std::{future::IntoFuture, time::Duration};
    use tlsn::{config::tls::TlsClientConfig, verifier::VerifierCommitStart};
    use tokio::io::AsyncReadExt;

    let (p_io, v_io) = tokio::io::duplex(1 << 17);
    let mut p_session = Session::new(p_io.compat());
    let mut v_session = Session::new(v_io.compat());
    let prover = p_session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = v_session
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();
    let (p_driver, p_handle) = p_session.split();
    let (v_driver, v_handle) = v_session.split();
    let p_task = tokio::spawn(p_driver);
    let v_task = tokio::spawn(v_driver);
    let config = ProxyTlsConfig::builder()
        .server_name(SERVER_DOMAIN.try_into().unwrap())
        .build()
        .unwrap();
    let (prover, verifier) = tokio::join!(prover.commit(config), async {
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await.unwrap() else {
            panic!("wrong mode")
        };
        verifier.accept().await.unwrap()
    });
    let (server_io, mut target) = tokio::io::duplex(1 << 16);
    let server_task = tokio::spawn(verifier.run(server_io.compat()));
    let close_task = tokio::spawn(async move {
        assert!(target.read(&mut [0; 1024]).await.unwrap() > 0);
    });
    let (_connection, prover) = prover
        .unwrap()
        .connect(
            TlsClientConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .build()
                .unwrap(),
        )
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), prover.into_future()).await;
    // Always clean up session drivers, including the negative-control timeout.
    p_handle.close();
    v_handle.close();
    p_task.abort();
    v_task.abort();
    server_task.abort();
    close_task.await.unwrap();
    let error = result
        .expect("target EOF left the handshake pending")
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("server closed during TLS handshake"),
        "{error}"
    );
}
