use tls_server_fixture::SERVER_DOMAIN;
use tlsn::{
    Session,
    config::{
        prover::ProverConfig,
        tls_commit::{
            TlsCommitConfig, TlsCommitProtocolConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig,
        },
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
use utils::{run_prover, run_verifier};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_mpc() {
    // Maximum number of bytes that can be sent from prover to server
    const MAX_SENT_DATA: usize = 1 << 12;
    // Maximum number of application records sent from prover to server
    const MAX_SENT_RECORDS: usize = 4;
    // Maximum number of bytes that can be received by prover from server
    const MAX_RECV_DATA: usize = 1 << 14;
    // Maximum number of application records received by prover from server
    const MAX_RECV_RECORDS: usize = 6;

    let config = TlsCommitConfig::builder()
        .protocol(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_sent_records(MAX_SENT_RECORDS)
                .max_recv_data(MAX_RECV_DATA)
                .max_recv_records_online(MAX_RECV_RECORDS)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    test(config).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_proxy() {
    let config = TlsCommitConfig::builder()
        .protocol(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    test(config).await;
}

async fn test(config: TlsCommitConfig) {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

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

    let ((_full_transcript, _prover_output), verifier_output) = match config.protocol() {
        TlsCommitProtocolConfig::Mpc(_) => {
            tokio::join!(
                run_prover(config, prover, Some(client_socket)),
                run_verifier(verifier, None)
            )
        }
        TlsCommitProtocolConfig::Proxy(_) => {
            tokio::join!(
                run_prover(config, prover, None),
                run_verifier(verifier, Some(client_socket))
            )
        }
        _ => panic!("unknown protocol config"),
    };

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
