mod common;

use tlsn::{
    Session,
    config::{prover::ProverConfig, tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::CA_CERT_DER;
use tokio_util::compat::TokioAsyncReadCompatExt;

use common::{finish_prover, run_prover_mpc, run_verifier};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mux_mpc_prover_verifier_native() {
    let _ = tracing_subscriber::fmt::try_init();

    const MAX_SENT_DATA: usize = 1 << 12;
    const MAX_SENT_RECORDS: usize = 4;
    const MAX_RECV_DATA: usize = 1 << 14;
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
    let server_task = tokio::spawn(tlsn_server_fixture::bind(server_socket.compat()));

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mux_mpc_high_throughput() {
    let _ = tracing_subscriber::fmt::try_init();

    const MAX_SENT_DATA: usize = 1 << 16;
    const MAX_SENT_RECORDS: usize = 64;
    const MAX_RECV_DATA: usize = 1 << 16;
    const MAX_RECV_RECORDS: usize = 64;

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
    let server_task = tokio::spawn(tlsn_server_fixture::bind(server_socket.compat()));

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
    assert!(!partial_transcript.is_complete());
}
