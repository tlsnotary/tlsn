//! Deferred-decryption semantics for MPC-TLS.
//!
//! This is a focused integration target, not a stress mode. It covers the
//! behavior that the main server/failure matrices intentionally pin to online
//! decryption:
//!
//! - when server response plaintext becomes readable,
//! - enabling decryption after the request vs after the response is buffered,
//! - `close_notify` before application data,
//! - `close_notify` after application data, with and without a TCP FIN.
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg tlsn_insecure" \
//!     cargo test -p tlsn --test deferred_decryption --profile tests-integration
//! ```

#![allow(unexpected_cfgs)]
#![cfg(tlsn_insecure)]

use std::{sync::OnceLock, time::Duration};

#[path = "support/stress.rs"]
mod stress;

use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use futures_rustls::{
    TlsAcceptor,
    pki_types::{CertificateDer as RustlsCert, PrivateKeyDer},
    rustls::ServerConfig,
};
use stress::{Jitter, Party, Plan, Point, Stress};
use tls_server_fixture::{
    APP_RECORD_LENGTH, CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER,
};
use tlsn::{
    Session, SessionHandle,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::ServerName,
    prover::{Prover, ProverControl, TlsConnection},
    verifier::{Verifier, VerifierCommitStart},
    webpki::{CertificateDer, RootCertStore},
};
use tokio::{
    sync::{Mutex, MutexGuard, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

const TIMEOUT: Duration = Duration::from_secs(15);
const BLOCK_TIMEOUT: Duration = Duration::from_millis(400);
const TRANSPORT_CAP: usize = 2 << 16;
const RESPONSE: &[u8] = b"deferred-response";

static STRESS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Stress loops in this module run many MPC sessions per test. Cargo runs test
/// functions in parallel, so serialize them when stress is enabled to avoid
/// starving the runtimes and timing out healthy sessions.
async fn lock_stress(stress: &Stress) -> Option<MutexGuard<'static, ()>> {
    if stress.enabled() {
        Some(STRESS_LOCK.get_or_init(|| Mutex::new(())).lock().await)
    } else {
        None
    }
}

type DriverTask = JoinHandle<()>;
type ProverTask = JoinHandle<tlsn::Result<()>>;
type VerifierTask = JoinHandle<tlsn::Result<()>>;
type MpcProver = Prover<tlsn::prover::state::CommitAccepted<tlsn::Mpc>>;
type MpcVerifier = Verifier<tlsn::verifier::state::CommitAccepted<tlsn::Mpc>>;

#[derive(Clone, Copy)]
enum ServerClose {
    /// Send the response and keep TCP open.
    KeepOpen,
    /// Send the response, then close_notify, and keep TCP open.
    CloseNotifyOpen,
    /// Send the response, then close_notify, then close TCP.
    CloseNotifyFin,
    /// Send the response, then close TCP without close_notify.
    Fin,
    /// Send the response, wait for the client to close, then close TCP.
    FinAfterSignal,
}

struct Harness {
    conn: TlsConnection,
    control: ProverControl,
    client_jitter: Option<Jitter>,
    prover_task: Option<ProverTask>,
    verifier_task: Option<VerifierTask>,
    server_task: Option<JoinHandle<()>>,
    ready: Option<oneshot::Receiver<()>>,
    p_handle: SessionHandle,
    v_handle: SessionHandle,
    p_driver: DriverTask,
    v_driver: DriverTask,
}

impl Harness {
    async fn wait_ready(&mut self) {
        self.ready
            .take()
            .expect("server readiness signal already consumed")
            .await
            .expect("server task should reach its scripted point");
    }

    async fn before(&mut self, point: Point) {
        if let Some(jitter) = self.client_jitter.as_mut() {
            jitter.delay(point).await;
        }
    }

    async fn send_request(&mut self) {
        self.before(Point::BeforeWrite).await;
        send_request(&mut self.conn).await;
    }

    async fn read_response(&mut self, expected: &[u8]) {
        self.before(Point::BeforeRead).await;
        read_response(&mut self.conn, expected).await;
    }

    async fn close(&mut self) {
        self.before(Point::BeforeClose).await;
        self.conn.close().await.unwrap();
    }

    async fn finish(mut self) -> (tlsn::Result<()>, tlsn::Result<()>) {
        let prover = self.prover_task.take().expect("prover task already taken");
        let verifier = self
            .verifier_task
            .take()
            .expect("verifier task already taken");

        let prover = timeout(TIMEOUT, prover)
            .await
            .expect("prover should finish")
            .expect("prover task should not panic");
        let verifier = timeout(TIMEOUT, verifier)
            .await
            .expect("verifier should finish")
            .expect("verifier task should not panic");

        (prover, verifier)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(task) = self.prover_task.take() {
            task.abort();
        }
        if let Some(task) = self.verifier_task.take() {
            task.abort();
        }
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        self.p_handle.close();
        self.v_handle.close();
        self.p_driver.abort();
        self.v_driver.abort();
    }
}

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

fn tls_client_config() -> TlsClientConfig {
    TlsClientConfig::builder()
        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
        .root_store(root_store())
        .build()
        .unwrap()
}

fn tls_server_config() -> std::sync::Arc<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = RustlsCert::from(SERVER_CERT_DER);
    std::sync::Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    )
}

fn mpc_config(defer_decryption: bool) -> MpcTlsConfig {
    MpcTlsConfig::builder()
        .max_sent_data(1 << 12)
        .max_sent_records(4)
        .max_recv_data(1 << 16)
        .max_recv_data_online(1 << 16)
        .max_recv_records_online(32)
        .defer_decryption_from_start(defer_decryption)
        .build()
        .unwrap()
}

fn pad(command: &[u8]) -> Vec<u8> {
    let mut record = command.to_vec();
    record.resize(APP_RECORD_LENGTH, 0);
    record
}

struct Sessions {
    prover: Prover,
    verifier: Verifier,
    p_handle: SessionHandle,
    v_handle: SessionHandle,
    p_task: DriverTask,
    v_task: DriverTask,
}

async fn new_sessions() -> Sessions {
    let (p_io, v_io) = tokio::io::duplex(2 << 23);
    let mut p_session = Session::new(p_io.compat());
    let mut v_session = Session::new(v_io.compat());

    let prover = p_session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = v_session
        .new_verifier(
            VerifierConfig::builder()
                .root_store(root_store())
                .build()
                .unwrap(),
        )
        .unwrap();

    let (p_driver, p_handle) = p_session.split();
    let (v_driver, v_handle) = v_session.split();
    let p_task = tokio::spawn(async move {
        let _ = p_driver.await;
    });
    let v_task = tokio::spawn(async move {
        let _ = v_driver.await;
    });

    Sessions {
        prover,
        verifier,
        p_handle,
        v_handle,
        p_task,
        v_task,
    }
}

async fn commit_mpc(
    sessions: Sessions,
    defer_decryption: bool,
) -> (
    MpcProver,
    MpcVerifier,
    SessionHandle,
    SessionHandle,
    DriverTask,
    DriverTask,
) {
    let Sessions {
        prover,
        verifier,
        p_handle,
        v_handle,
        p_task,
        v_task,
    } = sessions;

    let (prover, verifier) = tokio::join!(prover.commit(mpc_config(defer_decryption)), async {
        let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
            panic!("wrong mode")
        };
        verifier.accept().await.unwrap()
    });

    (
        prover.unwrap(),
        verifier,
        p_handle,
        v_handle,
        p_task,
        v_task,
    )
}

async fn scripted_server(
    socket: Compat<tokio::io::DuplexStream>,
    response: &'static [u8],
    close: ServerClose,
    ready: oneshot::Sender<()>,
    mut jitter: Option<Jitter>,
    fin_release: Option<oneshot::Receiver<()>>,
) {
    let acceptor = TlsAcceptor::from(tls_server_config());
    let mut conn = acceptor.accept(socket).await.unwrap();

    let mut request = [0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut request).await.unwrap();

    if !response.is_empty() {
        if let Some(jitter) = jitter.as_mut() {
            jitter.delay(Point::BeforeData).await;
        }
        conn.write_all(response).await.unwrap();
        conn.flush().await.unwrap();
    }

    match close {
        ServerClose::KeepOpen => {
            let _ = ready.send(());
            std::future::pending::<()>().await;
        }
        ServerClose::CloseNotifyOpen => {
            if let Some(jitter) = jitter.as_mut() {
                jitter.delay(Point::BeforeCloseNotify).await;
            }
            conn.get_mut().1.send_close_notify();
            conn.flush().await.unwrap();
            let _ = ready.send(());
            std::future::pending::<()>().await;
        }
        ServerClose::CloseNotifyFin => {
            if let Some(jitter) = jitter.as_mut() {
                jitter.delay(Point::BeforeCloseNotify).await;
            }
            conn.get_mut().1.send_close_notify();
            conn.flush().await.unwrap();
            let _ = ready.send(());

            if let Some(jitter) = jitter.as_mut() {
                jitter.delay(Point::BeforeFin).await;
            }
            drop(conn);
        }
        ServerClose::Fin => {
            let _ = ready.send(());

            if let Some(jitter) = jitter.as_mut() {
                jitter.delay(Point::BeforeFin).await;
            }
            drop(conn);
        }
        ServerClose::FinAfterSignal => {
            let _ = ready.send(());

            if let Some(jitter) = jitter.as_mut() {
                jitter.delay(Point::BeforeFin).await;
            }
            fin_release
                .expect("signal-ordered FIN needs a release channel")
                .await
                .expect("client should release the FIN");
            drop(conn);
        }
    }
}

async fn connect(defer_decryption: bool, response: &'static [u8], close: ServerClose) -> Harness {
    connect_with(defer_decryption, response, close, None, None).await
}

async fn connect_with(
    defer_decryption: bool,
    response: &'static [u8],
    close: ServerClose,
    plan: Option<&Plan>,
    fin_release: Option<oneshot::Receiver<()>>,
) -> Harness {
    let (prover, verifier, p_handle, v_handle, p_driver, v_driver) =
        commit_mpc(new_sessions().await, defer_decryption).await;

    let (client_io, server_peer) = tokio::io::duplex(TRANSPORT_CAP);
    let verifier_task = tokio::spawn(async move { verifier.run().await.map(drop) });

    let (ready_tx, ready_rx) = oneshot::channel();
    let server_task = tokio::spawn(scripted_server(
        server_peer.compat(),
        response,
        close,
        ready_tx,
        plan.map(|plan| plan.jitter(Party::Server)),
        fin_release,
    ));

    let (conn, prover) = prover
        .connect(tls_client_config(), client_io.compat())
        .unwrap();
    let control = prover.control();
    let prover_task = tokio::spawn(async move { prover.into_future().await.map(drop) });

    Harness {
        conn,
        control,
        client_jitter: plan.map(|plan| plan.jitter(Party::Client)),
        prover_task: Some(prover_task),
        verifier_task: Some(verifier_task),
        server_task: Some(server_task),
        ready: Some(ready_rx),
        p_handle,
        v_handle,
        p_driver,
        v_driver,
    }
}

async fn send_request(conn: &mut TlsConnection) {
    conn.write_all(&pad(b"request")).await.unwrap();
}

async fn read_response(conn: &mut TlsConnection, expected: &[u8]) {
    let mut buf = vec![0u8; expected.len()];
    timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("response should be readable")
        .expect("response read should not fail");
    assert_eq!(buf, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_close_notify_open_response_is_readable() {
    let stress = Stress::from_env();
    let _guard = lock_stress(&stress).await;
    for iteration in 0..stress.repeats() {
        let plan = stress.plan(iteration);
        online_close_notify_open_response_is_readable_case(&plan).await;
    }
}

async fn online_close_notify_open_response_is_readable_case(plan: &Plan) {
    let mut harness = connect_with(
        false,
        RESPONSE,
        ServerClose::CloseNotifyOpen,
        Some(plan),
        None,
    )
    .await;
    assert!(harness.control.is_decrypting());

    harness.send_request().await;
    harness.wait_ready().await;
    harness.read_response(RESPONSE).await;

    harness.close().await;
    let (prover, verifier) = harness.finish().await;
    prover.unwrap();
    verifier.unwrap();
}

/// Known limitation / pending design decision: mid-session decryption toggling.
///
/// It is undecided whether enabling decryption mid-session is supported at
/// all, and if so whether it decrypts already-buffered application data
/// (the historical notifier behavior) or only records arriving after the
/// toggle. There is currently no wake-up path for a parked prover, so the
/// read times out. Unignore once the semantics and wake-up behavior are
/// specified.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "mid-session decryption toggle is unspecified and currently has no wake-up path"]
async fn deferred_response_waits_until_decryption_is_enabled() {
    let mut harness = connect(true, RESPONSE, ServerClose::KeepOpen).await;
    assert!(!harness.control.is_decrypting());

    send_request(&mut harness.conn).await;
    harness.wait_ready().await;

    let mut buf = vec![0u8; RESPONSE.len()];
    let blocked = timeout(BLOCK_TIMEOUT, harness.conn.read_exact(&mut buf)).await;
    assert!(
        blocked.is_err(),
        "deferred response must not be readable before decryption is enabled"
    );

    harness.control.enable_decryption(true);
    read_response(&mut harness.conn, RESPONSE).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_enable_after_request_reads_response_with_close_notify_open() {
    let stress = Stress::from_env();
    let _guard = lock_stress(&stress).await;
    for iteration in 0..stress.repeats() {
        let plan = stress.plan(iteration);
        deferred_enable_after_request_reads_response_case(&plan).await;
    }
}

async fn deferred_enable_after_request_reads_response_case(plan: &Plan) {
    let mut harness = connect_with(
        true,
        RESPONSE,
        ServerClose::CloseNotifyOpen,
        Some(plan),
        None,
    )
    .await;
    assert!(!harness.control.is_decrypting());

    harness.send_request().await;
    harness.control.enable_decryption(true);
    harness.wait_ready().await;

    harness.read_response(RESPONSE).await;

    harness.close().await;
    let (prover, verifier) = harness.finish().await;
    prover.unwrap();
    verifier.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_close_notify_before_data_is_ok() {
    let stress = Stress::from_env();
    let _guard = lock_stress(&stress).await;
    for iteration in 0..stress.repeats() {
        let plan = stress.plan(iteration);
        deferred_close_notify_before_data_is_ok_case(&plan).await;
    }
}

async fn deferred_close_notify_before_data_is_ok_case(plan: &Plan) {
    let mut harness = connect_with(true, b"", ServerClose::CloseNotifyOpen, Some(plan), None).await;

    harness.send_request().await;
    harness.wait_ready().await;
    harness.close().await;

    let (prover, verifier) = harness.finish().await;
    prover.unwrap();
    verifier.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_response_then_fin_completes_without_decryption() {
    let stress = Stress::from_env();
    let _guard = lock_stress(&stress).await;
    for iteration in 0..stress.repeats() {
        let plan = stress.plan(iteration);
        deferred_response_then_fin_completes_case(&plan).await;
    }
}

async fn deferred_response_then_fin_completes_case(plan: &Plan) {
    let mut harness = connect_with(true, RESPONSE, ServerClose::Fin, Some(plan), None).await;

    harness.send_request().await;
    harness.wait_ready().await;
    harness.close().await;

    let (prover, verifier) = harness.finish().await;
    prover.unwrap();
    verifier.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_response_then_fin_after_client_close_completes() {
    let stress = Stress::from_env();
    let _guard = lock_stress(&stress).await;
    for iteration in 0..stress.repeats() {
        let plan = stress.plan(iteration);
        deferred_response_then_fin_after_client_close_case(&plan).await;
    }
}

async fn deferred_response_then_fin_after_client_close_case(plan: &Plan) {
    let (fin_tx, fin_rx) = oneshot::channel();
    let mut harness = connect_with(
        true,
        RESPONSE,
        ServerClose::FinAfterSignal,
        Some(plan),
        Some(fin_rx),
    )
    .await;

    harness.send_request().await;
    harness.wait_ready().await;
    harness.close().await;
    fin_tx.send(()).expect("server should wait for FIN release");

    let (prover, verifier) = harness.finish().await;
    prover.unwrap();
    verifier.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_response_close_notify_then_fin_completes_without_decryption() {
    let stress = Stress::from_env();
    let _guard = lock_stress(&stress).await;
    for iteration in 0..stress.repeats() {
        let plan = stress.plan(iteration);
        deferred_response_close_notify_then_fin_completes_case(&plan).await;
    }
}

async fn deferred_response_close_notify_then_fin_completes_case(plan: &Plan) {
    let mut harness = connect_with(
        true,
        RESPONSE,
        ServerClose::CloseNotifyFin,
        Some(plan),
        None,
    )
    .await;

    harness.send_request().await;
    harness.wait_ready().await;
    harness.close().await;

    let (prover, verifier) = harness.finish().await;
    prover.unwrap();
    verifier.unwrap();
}

/// Known limitation: the close_notify is queued behind deferred application
/// data, so the prover never observes the peer's TLS close when TCP stays open.
///
/// This path is pending an upstream fix where close_notify is recognized even
/// with deferred decryption. Unignore once that fix lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "pending upstream fix: recognize close_notify under deferred decryption"]
async fn deferred_response_close_notify_open_completes() {
    let mut harness = connect(true, RESPONSE, ServerClose::CloseNotifyOpen).await;

    send_request(&mut harness.conn).await;
    harness.wait_ready().await;
    harness.conn.close().await.unwrap();

    let (prover, verifier) = harness.finish().await;
    prover.unwrap();
    verifier.unwrap();
}
