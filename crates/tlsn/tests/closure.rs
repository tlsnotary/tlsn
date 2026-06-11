//! Tests for TLS connection-closure semantics in MPC mode.
//!
//! These run against the raw TLS server fixture which reacts to magic
//! payloads, allowing us to exercise clean closure (close_notify), abrupt
//! socket closure and fatal alerts.

use futures::{AsyncReadExt, AsyncWriteExt};
use tls_server_fixture::{APP_RECORD_LENGTH, CA_CERT_DER, SERVER_DOMAIN, bind_test_server};
use tlsn::{
    Session, SessionHandle,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::ServerName,
    prover::Prover,
    verifier::{Verifier, VerifierCommitStart},
    webpki::{CertificateDer, RootCertStore},
};
use tokio::io::DuplexStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

type TestError = Box<dyn std::error::Error + Send + Sync>;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_SENT_RECORDS: usize = 4;
const MAX_RECV_DATA: usize = 1 << 14;
const MAX_RECV_RECORDS: usize = 6;

/// Exercises the TLS connection-closure scenarios in MPC mode.
///
/// The scenarios run sequentially inside this single test, and thus on a
/// single tokio runtime. They are deliberately *not* split into separate
/// `#[test]` functions: the default harness would then run them in parallel,
/// and several concurrent MPC sessions in one process deadlock contending for
/// the MPC backend's process-global resources (most notably the shared
/// `rayon` thread pool). Running them one at a time avoids that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_mpc_connection_closure() {
    server_close_notify().await;
    server_closes_uncleanly().await;
    server_closes_uncleanly_no_data().await;
    server_alert().await;
}

/// The server sends close_notify and closes the socket. The connection
/// closes cleanly and MPC-TLS finalization succeeds on both sides.
async fn server_close_notify() {
    let setup = Setup::new().await;
    let server_task = tokio::spawn(bind_test_server(setup.server_socket.compat()));

    let prover_fut = run_prover(
        setup.prover,
        setup.client_socket,
        Scenario {
            echo_first: true,
            command: b"send_close_notify_and_close_socket",
            close: true,
        },
    );
    let verifier_fut = run_verifier_commit(setup.verifier);

    let (prover_result, verifier_result) = tokio::join!(prover_fut, verifier_fut);

    prover_result.expect("prover should finalize after clean closure");
    verifier_result.expect("verifier should finalize after clean closure");
    server_task.await.unwrap();
}

/// The server closes the socket abruptly without sending close_notify,
/// after having sent application data. The transcripts end with application
/// records, which the record-layer closure check accepts, so finalization
/// still succeeds.
async fn server_closes_uncleanly() {
    let setup = Setup::new().await;
    let server_task = tokio::spawn(bind_test_server(setup.server_socket.compat()));

    let prover_fut = run_prover(
        setup.prover,
        setup.client_socket,
        Scenario {
            echo_first: true,
            command: b"close_socket",
            close: false,
        },
    );
    let verifier_fut = run_verifier_commit(setup.verifier);

    let (prover_result, verifier_result) = tokio::join!(prover_fut, verifier_fut);

    prover_result.expect("prover should finalize after abrupt closure");
    verifier_result.expect("verifier should finalize after abrupt closure");
    server_task.await.unwrap();
}

/// The server closes the socket abruptly right after the handshake, without
/// any application data. The received transcript then ends with a handshake
/// record, which both the leader and the follower must reject.
async fn server_closes_uncleanly_no_data() {
    let setup = Setup::new().await;
    let server_task = tokio::spawn(bind_test_server(setup.server_socket.compat()));

    let prover_fut = run_prover(
        setup.prover,
        setup.client_socket,
        Scenario {
            echo_first: false,
            command: b"close_socket",
            close: false,
        },
    );
    let verifier_task = tokio::spawn(run_verifier_commit(setup.verifier));

    prover_fut
        .await
        .expect_err("prover must not finalize when no application data was received");

    let verifier_result = tokio::time::timeout(std::time::Duration::from_secs(60), verifier_task)
        .await
        .expect("verifier should not hang")
        .unwrap();
    verifier_result.expect_err("verifier must not finalize when no application data was received");

    server_task.abort();
}

/// The server sends a fatal alert. The transcript ends with an alert that
/// is not close_notify, which neither the leader nor the follower must
/// accept.
async fn server_alert() {
    let setup = Setup::new().await;
    let server_task = tokio::spawn(bind_test_server(setup.server_socket.compat()));

    let prover_fut = run_prover(
        setup.prover,
        setup.client_socket,
        Scenario {
            echo_first: false,
            command: b"send_alert",
            close: false,
        },
    );
    let verifier_task = tokio::spawn(run_verifier_commit(setup.verifier));

    prover_fut
        .await
        .expect_err("prover must not finalize after a fatal alert");

    // The follower aborts once the leader is gone; it must not finalize
    // successfully.
    let verifier_result = tokio::time::timeout(std::time::Duration::from_secs(60), verifier_task)
        .await
        .expect("verifier should not hang")
        .unwrap();
    verifier_result.expect_err("verifier must not finalize after a fatal alert");

    server_task.abort();
}

struct Setup {
    prover: Prover,
    verifier: Verifier,
    client_socket: DuplexStream,
    server_socket: DuplexStream,
    _handles: (SessionHandle, SessionHandle),
}

impl Setup {
    async fn new() -> Self {
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

        let (session_p_driver, session_p_handle) = session_p.split();
        let (session_v_driver, session_v_handle) = session_v.split();

        tokio::spawn(session_p_driver);
        tokio::spawn(session_v_driver);

        let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

        Self {
            prover,
            verifier,
            client_socket,
            server_socket,
            _handles: (session_p_handle, session_v_handle),
        }
    }
}

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

/// Interaction with the raw test server.
struct Scenario {
    /// Exchange one round of application data before sending the command,
    /// so that the received transcript contains application records.
    echo_first: bool,
    /// The command for the raw test server, sent as the final record.
    command: &'static [u8],
    /// Whether the client sends close_notify after the command.
    close: bool,
}

/// Runs the MPC prover against the raw test server: sends commands as
/// zero-padded application records and then drives the connection to
/// closure.
async fn run_prover(
    prover: Prover,
    client_socket: DuplexStream,
    scenario: Scenario,
) -> Result<(), TestError> {
    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let prover = prover.commit(config).await?;

    let (mut tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
            .root_store(root_store())
            .build()
            .unwrap(),
        client_socket.compat(),
    )?;
    let mut prover_task = tokio::spawn(prover.into_future());

    if scenario.echo_first {
        // Any unrecognized payload makes the server respond with "hello".
        // The response is not read here: decryption is deferred by default,
        // so the plaintext only becomes available at closure. It still ends
        // up in the received transcript as an application record.
        tls_connection.write_all(&pad_record(b"echo")).await?;
    }

    tls_connection
        .write_all(&pad_record(scenario.command))
        .await?;

    if scenario.close {
        tls_connection.close().await?;
    }

    // Drain the connection while driving the prover. If MPC-TLS fails, the
    // prover future errors without closing the connection handle, so the
    // read may never resolve: race the two.
    let mut buf = Vec::new();
    let prover = tokio::select! {
        res = &mut prover_task => res.unwrap()?,
        _ = tls_connection.read_to_end(&mut buf) => prover_task.await.unwrap()?,
    };
    prover.close().await?;

    Ok(())
}

/// Pads a command to a full record, as expected by the raw test server,
/// which reads records of exactly `APP_RECORD_LENGTH` bytes.
fn pad_record(command: &[u8]) -> Vec<u8> {
    let mut record = command.to_vec();
    record.resize(APP_RECORD_LENGTH, 0);
    record
}

/// Runs the verifier through the MPC commit phase and closes the session.
async fn run_verifier_commit(verifier: Verifier) -> Result<(), TestError> {
    let verifier = verifier.commit().await?;

    let VerifierCommitStart::Mpc(verifier) = verifier else {
        panic!("expected MPC commit protocol");
    };

    let verifier = verifier.accept().await?.run().await?;
    verifier.close().await?;

    Ok(())
}
