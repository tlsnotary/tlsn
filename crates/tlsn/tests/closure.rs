//! Session-lifecycle deep-dive: dropping an unsplit session must cancel its
//! participants.
//!
//! Server termination and fault reactions are covered by `server_behaviour.rs`;
//! actor disappearance phases are covered by `failure_table.rs`. This file
//! keeps only the lifecycle case that neither matrix expresses.
//!
//! This needs `tlsn_insecure` so the MPC setup is cheap. Run it with:
//!
//! ```text
//! RUSTFLAGS="--cfg tlsn_insecure" \
//!     cargo test -p tlsn --test closure --profile tests-integration -- --include-ignored
//! ```

#![allow(unexpected_cfgs)]
#![cfg(tlsn_insecure)]

use std::time::Duration;

use futures::AsyncWriteExt;
use tls_server_fixture::{APP_RECORD_LENGTH, CA_CERT_DER, SERVER_DOMAIN, bind_test_server};
use tlsn::{
    Session,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::ServerName,
    verifier::{Verifier, VerifierCommitStart},
    webpki::{CertificateDer, RootCertStore},
};
use tokio_util::compat::TokioAsyncReadCompatExt;

type TestError = Box<dyn std::error::Error + Send + Sync>;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_SENT_RECORDS: usize = 4;
const MAX_RECV_DATA: usize = 1 << 14;
const MAX_RECV_RECORDS: usize = 6;

/// Dropping a session that was never split must cancel its participants.
///
/// The prover is parked on a server that keeps the connection open without
/// closing, so no mux I/O of its own can wake it: only the session closure
/// can. If the task driving the unsplit session is aborted, the prover must
/// fail instead of hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn unsplit_session_drop_cancels_prover() {
    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(root_store())
                .build()
                .unwrap(),
        )
        .unwrap();

    // The prover's session is deliberately never split: drive it as a future
    // so that aborting the task drops the session.
    let prover_session = tokio::spawn(async move {
        let _ = session_p.await;
    });

    // The verifier uses the usual split path and stays alive, so the prover's
    // failure is attributable to its own session being dropped.
    let (verifier_driver, _verifier_handle) = session_v.split();
    tokio::spawn(verifier_driver);
    let verifier_task = tokio::spawn(run_verifier_commit(verifier));

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind_test_server(server_socket.compat()));

    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let prover = prover.commit(config).await.expect("prover should commit");
    let (mut tls_connection, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(root_store())
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .expect("prover should connect");
    let mut prover_task = tokio::spawn(prover.into_future());

    // The server echoes once and then stays open, so the prover parks waiting
    // for closure. Confirm it is actually parked before dropping the session;
    // otherwise this would only exercise the `is_closed` fast path.
    tls_connection
        .write_all(&pad_record(b"echo"))
        .await
        .expect("prover should write the request");
    tokio::time::timeout(Duration::from_secs(10), &mut prover_task)
        .await
        .expect_err("prover should be parked on the silent server");

    // Abort the only driver of the unsplit session. Dropping it must close the
    // session closure and wake the parked prover.
    prover_session.abort();
    let _ = prover_session.await;

    let prover_result = tokio::time::timeout(Duration::from_secs(10), prover_task)
        .await
        .expect("prover should be cancelled when its unsplit session is dropped")
        .expect("prover task should not panic");
    prover_result.expect_err("prover must not finalize after its session is dropped");

    // The verifier loses its peer and must terminate as well.
    let verifier_result = tokio::time::timeout(Duration::from_secs(10), verifier_task)
        .await
        .expect("verifier should not hang after the prover session is dropped")
        .expect("verifier task should not panic");
    verifier_result.expect_err("verifier must not finalize after the prover session is dropped");

    server_task.abort();
}

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

fn pad_record(command: &[u8]) -> Vec<u8> {
    let mut record = command.to_vec();
    record.resize(APP_RECORD_LENGTH, 0);
    record
}

async fn run_verifier_commit(verifier: Verifier) -> Result<(), TestError> {
    let verifier = verifier.commit().await?;

    let VerifierCommitStart::Mpc(verifier) = verifier else {
        panic!("expected MPC commit protocol");
    };

    let verifier = verifier.accept().await?.run().await?;
    verifier.close().await?;

    Ok(())
}
