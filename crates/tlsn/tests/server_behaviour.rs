//! Server-behaviour matrix: how the prover and verifier react to how the
//! server ends or misbehaves.
//!
//! This is a separate axis from `failure_table.rs`, which covers actor
//! disappearance (who left and when) plus ordering of two losses. Rows that
//! combine a loss with a server close stay there when the ordering is the
//! point; this file owns pure server outcomes.
//!
//! # Coverage
//!
//! Connected (after the handshake):
//!
//! ```text
//!                         close_notify   close_notify+FIN   FIN only   alert   corrupted   bad MAC   silent   streaming
//! MPC                     ok             ok                 ok         err     err         err       hang     ok
//! Proxy                   ok             ok                 complete*  err     err         err       hang     ok
//! ```
//!
//! Proxy `close_notify` is `ok` even if the application handle stays open: the
//! proxy answers the server's alert immediately and late writes are rejected.
//! The EOF-reading variant is pinned by its own row. Proxy `silent` stays
//! `hang` even after the client closes, because the server never signals that
//! its side is finished. `FIN only` in proxy is
//! `complete` (OK or Err) because the
//! verifier owns the server socket and reports the loss itself. `FIN only`
//! without any application data is `err` in both modes: the transcript ends
//! with a handshake record.
//!
//! Mid-handshake:
//!
//! ```text
//!                         FIN only   fatal alert   corrupted record
//! MPC                     err        err           err
//! Proxy                   err        err           err
//! ```
//!
//! Not covered here: bad MAC mid-handshake is impossible (no application
//! keys), and close_notify mid-handshake is a protocol violation. The closing
//! phase (client close_notify in flight) is covered by the half-close ordering
//! rows in `failure_table.rs`.
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg tlsn_insecure" \
//!     cargo test -p tlsn --test server_behaviour --profile tests-integration
//! ```

#![allow(unexpected_cfgs)]
#![cfg(tlsn_insecure)]

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[path = "support/counting_io.rs"]
mod counting_io;
#[path = "support/stress.rs"]
mod stress;
use counting_io::CountingIo;
use stress::{Gate, Jitter, Party, Plan, Point, RacePoint, Stress};

use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use futures_rustls::{
    TlsAcceptor,
    pki_types::{CertificateDer as RustlsCert, PrivateKeyDer},
    rustls::ServerConfig,
};
use tls_server_fixture::{
    APP_RECORD_LENGTH, CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER,
    bind_test_server,
};
use tlsn::{
    Session, SessionHandle,
    config::{
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    prover::Prover,
    verifier::{Verifier, VerifierCommitStart},
    webpki::{CertificateDer, RootCertStore},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    sync::Notify,
    task::JoinHandle,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

const TIMEOUT: Duration = Duration::from_secs(60);
const ROLE_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSPORT_CAP: usize = 2 << 16;
const STREAM_RECORDS: usize = 4;

const FATAL_ALERT: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
const CORRUPTED_RECORD: &[u8] = &[1u8; 18];

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Mode {
    Mpc,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum State {
    MidHandshake,
    Connected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Behaviour {
    CloseNotifyOnly,
    /// Like `CloseNotifyOnly`, but the client reads until EOF before closing.
    CloseNotifyOnlyEof,
    /// Sends `hello` and close_notify, then expects the client's close_notify.
    /// Late application writes must be rejected.
    CloseNotifyThenRejectWrites,
    /// Sends `hello`, then closes TCP without a TLS close_notify.
    ResponseThenFin,
    CloseNotifyThenFin,
    FinOnly,
    FinOnlyNoData,
    FatalAlert,
    CorruptedRecord,
    BadMac,
    Silent,
    Streaming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Ok,
    Err,
    Complete,
    Hang,
}

/// Why a row is allowed to hang.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HangCause {
    /// The server transport is alive but sends nothing further.
    SilentServer,
    /// The application handle is alive and has not closed.
    OpenClient,
    /// The peer's application object is gone, but its session driver/transport
    /// is still running, so nobody will close it.
    OrphanedTransport,
}

#[derive(Debug, Clone, Copy)]
struct Case {
    name: &'static str,
    mode: Mode,
    state: State,
    behaviour: Behaviour,
    /// Whether the client half-closes after its request.
    client_close: bool,
    prover: Option<Expect>,
    verifier: Option<Expect>,
    /// Why a hanging role is allowed to wait.
    hang: Option<HangCause>,
}

const fn case(
    name: &'static str,
    mode: Mode,
    state: State,
    behaviour: Behaviour,
    client_close: bool,
    prover: Option<Expect>,
    verifier: Option<Expect>,
) -> Case {
    Case {
        name,
        mode,
        state,
        behaviour,
        client_close,
        prover,
        verifier,
        hang: None,
    }
}

const fn case_hang(
    name: &'static str,
    mode: Mode,
    state: State,
    behaviour: Behaviour,
    client_close: bool,
    prover: Option<Expect>,
    verifier: Option<Expect>,
    hang: HangCause,
) -> Case {
    Case {
        name,
        mode,
        state,
        behaviour,
        client_close,
        prover,
        verifier,
        hang: Some(hang),
    }
}

const CASES: &[Case] = &[
    // --- Connected ------------------------------------------------------
    case(
        "mpc close_notify only, client open",
        Mode::Mpc,
        State::Connected,
        Behaviour::CloseNotifyOnly,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // The proxy answers the server's close_notify immediately, so the session
    // can finish even though the application handle stays open after reading
    // the response.
    case(
        "proxy close_notify only, client open",
        Mode::Proxy,
        State::Connected,
        Behaviour::CloseNotifyOnly,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "mpc close_notify only, client close",
        Mode::Mpc,
        State::Connected,
        Behaviour::CloseNotifyOnly,
        true,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "proxy close_notify only, client close",
        Mode::Proxy,
        State::Connected,
        Behaviour::CloseNotifyOnly,
        true,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // The app reads until EOF after the server's close_notify even though the
    // server keeps TCP open, then closes normally.
    case(
        "proxy close_notify only, client reads to eof",
        Mode::Proxy,
        State::Connected,
        Behaviour::CloseNotifyOnlyEof,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // Inbound finishes first: the app reads EOF, then attempts a late write.
    // TLS 1.2 requires an immediate close_notify response and discarding
    // pending writes, so the write must fail in both modes.
    case(
        "mpc close_notify then late write rejected",
        Mode::Mpc,
        State::Connected,
        Behaviour::CloseNotifyThenRejectWrites,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "proxy close_notify then late write rejected",
        Mode::Proxy,
        State::Connected,
        Behaviour::CloseNotifyThenRejectWrites,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // The server sends a response and then FINs without close_notify. The app
    // must receive the buffered response before observing closure.
    case(
        "mpc response then fin, client reads",
        Mode::Mpc,
        State::Connected,
        Behaviour::ResponseThenFin,
        false,
        Some(Expect::Complete),
        Some(Expect::Complete),
    ),
    case(
        "proxy response then fin, client reads",
        Mode::Proxy,
        State::Connected,
        Behaviour::ResponseThenFin,
        false,
        Some(Expect::Complete),
        Some(Expect::Complete),
    ),
    case(
        "mpc close_notify then FIN",
        Mode::Mpc,
        State::Connected,
        Behaviour::CloseNotifyThenFin,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "proxy close_notify then FIN",
        Mode::Proxy,
        State::Connected,
        Behaviour::CloseNotifyThenFin,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "mpc FIN only",
        Mode::Mpc,
        State::Connected,
        Behaviour::FinOnly,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "proxy FIN only",
        Mode::Proxy,
        State::Connected,
        Behaviour::FinOnly,
        false,
        Some(Expect::Complete),
        Some(Expect::Complete),
    ),
    case(
        "mpc FIN only, no app data",
        Mode::Mpc,
        State::Connected,
        Behaviour::FinOnlyNoData,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "proxy FIN only, no app data",
        Mode::Proxy,
        State::Connected,
        Behaviour::FinOnlyNoData,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "mpc fatal alert",
        Mode::Mpc,
        State::Connected,
        Behaviour::FatalAlert,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "proxy fatal alert",
        Mode::Proxy,
        State::Connected,
        Behaviour::FatalAlert,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "mpc corrupted record",
        Mode::Mpc,
        State::Connected,
        Behaviour::CorruptedRecord,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "proxy corrupted record",
        Mode::Proxy,
        State::Connected,
        Behaviour::CorruptedRecord,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "mpc bad MAC",
        Mode::Mpc,
        State::Connected,
        Behaviour::BadMac,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "proxy bad MAC",
        Mode::Proxy,
        State::Connected,
        Behaviour::BadMac,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case_hang(
        "mpc silent",
        Mode::Mpc,
        State::Connected,
        Behaviour::Silent,
        false,
        Some(Expect::Hang),
        Some(Expect::Hang),
        HangCause::SilentServer,
    ),
    case_hang(
        "proxy silent",
        Mode::Proxy,
        State::Connected,
        Behaviour::Silent,
        false,
        Some(Expect::Hang),
        Some(Expect::Hang),
        HangCause::SilentServer,
    ),
    // The client closes, but the server neither sends close_notify nor closes
    // TCP. The session is a live but silent peer, so waiting is deliberate.
    case_hang(
        "proxy silent, client close",
        Mode::Proxy,
        State::Connected,
        Behaviour::Silent,
        true,
        Some(Expect::Hang),
        Some(Expect::Hang),
        HangCause::SilentServer,
    ),
    case(
        "mpc streaming",
        Mode::Mpc,
        State::Connected,
        Behaviour::Streaming,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    case(
        "proxy streaming",
        Mode::Proxy,
        State::Connected,
        Behaviour::Streaming,
        false,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // The client half-closes while the server is still streaming.
    case(
        "mpc streaming, client close",
        Mode::Mpc,
        State::Connected,
        Behaviour::Streaming,
        true,
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // In proxy mode the client disappearing mid-stream can abort the proxy
    // session; require only that both roles terminate.
    case(
        "proxy streaming, client close",
        Mode::Proxy,
        State::Connected,
        Behaviour::Streaming,
        true,
        Some(Expect::Complete),
        Some(Expect::Complete),
    ),
    // --- Mid-handshake --------------------------------------------------
    case(
        "mpc FIN only mid-handshake",
        Mode::Mpc,
        State::MidHandshake,
        Behaviour::FinOnly,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "proxy FIN only mid-handshake",
        Mode::Proxy,
        State::MidHandshake,
        Behaviour::FinOnly,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "mpc fatal alert mid-handshake",
        Mode::Mpc,
        State::MidHandshake,
        Behaviour::FatalAlert,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "proxy fatal alert mid-handshake",
        Mode::Proxy,
        State::MidHandshake,
        Behaviour::FatalAlert,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "mpc corrupted record mid-handshake",
        Mode::Mpc,
        State::MidHandshake,
        Behaviour::CorruptedRecord,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    case(
        "proxy corrupted record mid-handshake",
        Mode::Proxy,
        State::MidHandshake,
        Behaviour::CorruptedRecord,
        false,
        Some(Expect::Err),
        Some(Expect::Err),
    ),
];

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Outcome {
    Ok,
    Err(String),
    Panic(String),
    Timeout,
}

fn check(case: &Case, role: &str, expected: Expect, actual: Outcome) {
    eprintln!(
        "{} [{:?} × {:?} × {:?}] {role}: {actual:?} (expected {expected:?})",
        case.name, case.mode, case.state, case.behaviour
    );
    let valid = match expected {
        Expect::Ok => matches!(actual, Outcome::Ok),
        Expect::Err => matches!(actual, Outcome::Err(_)),
        Expect::Complete => matches!(actual, Outcome::Ok | Outcome::Err(_)),
        Expect::Hang => matches!(actual, Outcome::Timeout),
    };
    assert!(
        valid,
        "{}: {role}: expected {expected:?}, got {actual:?}",
        case.name
    );
}

fn outcome_from_join(res: Result<tlsn::Result<()>, tokio::task::JoinError>) -> Outcome {
    match res {
        Ok(Ok(())) => Outcome::Ok,
        Ok(Err(err)) => Outcome::Err(err.to_string()),
        Err(join) if join.is_panic() => Outcome::Panic(format!("{:?}", join.into_panic())),
        Err(join) => Outcome::Panic(format!("cancelled: {join}")),
    }
}

async fn observe_roles(
    prover: Option<ProverTask>,
    verifier: Option<VerifierTask>,
    timeout: Duration,
) -> (Option<Outcome>, Option<Outcome>) {
    let mut prover_task = prover;
    let mut verifier_task = verifier;
    let mut prover_out = None;
    let mut verifier_out = None;

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    loop {
        if prover_task.is_none() && verifier_task.is_none() {
            break;
        }

        tokio::select! {
            biased;
            _ = &mut deadline => {
                if let Some(task) = prover_task.as_mut() {
                    task.abort();
                    prover_out = Some(Outcome::Timeout);
                }
                if let Some(task) = verifier_task.as_mut() {
                    task.abort();
                    verifier_out = Some(Outcome::Timeout);
                }
                break;
            }
            res = async {
                match prover_task.as_mut() {
                    Some(task) => task.await,
                    None => unreachable!("disabled prover branch was polled"),
                }
            }, if prover_task.is_some() => {
                prover_out = Some(outcome_from_join(res));
                prover_task = None;
            }
            res = async {
                match verifier_task.as_mut() {
                    Some(task) => task.await,
                    None => unreachable!("disabled verifier branch was polled"),
                }
            }, if verifier_task.is_some() => {
                verifier_out = Some(outcome_from_join(res));
                verifier_task = None;
            }
        }
    }

    (prover_out, verifier_out)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type DriverTask = JoinHandle<()>;
type ProverTask = JoinHandle<tlsn::Result<()>>;
type VerifierTask = JoinHandle<tlsn::Result<()>>;
type MpcProver = Prover<tlsn::prover::state::CommitAccepted<tlsn::Mpc>>;
type MpcVerifier = Verifier<tlsn::verifier::state::CommitAccepted<tlsn::Mpc>>;
type ProxyProver = Prover<tlsn::prover::state::CommitAccepted<tlsn::Proxy>>;
type ProxyVerifier = Verifier<tlsn::verifier::state::CommitAccepted<tlsn::Proxy>>;

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

/// Runs a participant task with jitter at entry and exit.
///
/// The library itself stays jitter-free; only harness-owned task boundaries
/// are delayed.
fn spawn_prover_task<F, T>(mut jitter: Jitter, future: F) -> JoinHandle<tlsn::Result<()>>
where
    F: Future<Output = tlsn::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(async move {
        jitter.delay(Point::BeforeWrite).await;
        let result = future.await.map(drop);
        jitter.delay(Point::BeforeClose).await;
        result
    })
}

fn spawn_verifier_task<F, T>(mut jitter: Jitter, future: F) -> JoinHandle<tlsn::Result<()>>
where
    F: Future<Output = tlsn::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(async move {
        jitter.delay(Point::BeforeRead).await;
        let result = future.await.map(drop);
        jitter.delay(Point::BeforeClose).await;
        result
    })
}

async fn commit_mpc(
    sessions: Sessions,
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
    let (prover, verifier) = tokio::join!(prover.commit(mpc_config()), async {
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

async fn commit_proxy(
    sessions: Sessions,
) -> (
    ProxyProver,
    ProxyVerifier,
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
    let (prover, verifier) = tokio::join!(prover.commit(proxy_config()), async {
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await.unwrap() else {
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

fn mpc_config() -> MpcTlsConfig {
    MpcTlsConfig::builder()
        .max_sent_data(1 << 12)
        .max_sent_records(4)
        .max_recv_data(1 << 16)
        .max_recv_data_online(1 << 16)
        .max_recv_records_online(32)
        .defer_decryption_from_start(false)
        .build()
        .unwrap()
}

fn proxy_config() -> ProxyTlsConfig {
    ProxyTlsConfig::builder()
        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
        .build()
        .unwrap()
}

fn pad(command: &[u8]) -> Vec<u8> {
    let mut record = command.to_vec();
    record.resize(APP_RECORD_LENGTH, 0);
    record
}

fn tls_server_config() -> Arc<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = RustlsCert::from(SERVER_CERT_DER);
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    )
}

/// Echoes one record, sends `close_notify`, then keeps the TCP connection open.
async fn close_notify_only_server(
    socket: Compat<CountingIo<DuplexStream>>,
    sent: Arc<Mutex<Vec<u8>>>,
    quiet: Arc<Notify>,
    received: Arc<Mutex<Vec<u8>>>,
    expect_close_notify: bool,
    close_gate: Option<Arc<Gate>>,
    mut jitter: Jitter,
) {
    let acceptor = TlsAcceptor::from(tls_server_config());
    let mut conn = acceptor.accept(socket).await.unwrap();

    jitter.delay(Point::BeforeRead).await;
    let mut buf = [0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut buf).await.unwrap();
    received.lock().unwrap().extend_from_slice(&buf);
    jitter.delay(Point::BeforeData).await;
    sent.lock().unwrap().extend_from_slice(b"hello");
    conn.write_all(b"hello").await.unwrap();
    conn.flush().await.unwrap();

    let server_first = match close_gate.as_ref() {
        Some(gate) => gate.wait(Party::Server).await,
        None => false,
    };

    jitter.delay(Point::BeforeCloseNotify).await;
    conn.get_mut().1.send_close_notify();
    conn.flush().await.unwrap();

    if server_first {
        close_gate.as_ref().expect("first side needs a gate").open();
    }

    if expect_close_notify {
        jitter.delay(Point::BeforeRead).await;
        let n = conn.read(&mut [0u8; 1]).await.unwrap();
        assert_eq!(n, 0, "server should see a clean close_notify");
    }

    quiet.notify_one();
    std::future::pending::<()>().await;
}

/// Sends `hello` and close_notify, then expects only the client's close_notify.
///
/// The TCP connection stays open. A TLS 1.2 peer must answer the close_notify
/// immediately and must not send application data afterwards.
async fn close_notify_then_reject_writes_server(
    socket: Compat<CountingIo<DuplexStream>>,
    sent: Arc<Mutex<Vec<u8>>>,
    received: Arc<Mutex<Vec<u8>>>,
    quiet: Arc<Notify>,
    mut jitter: Jitter,
) {
    let acceptor = TlsAcceptor::from(tls_server_config());
    let mut conn = acceptor.accept(socket).await.unwrap();

    jitter.delay(Point::BeforeRead).await;
    let mut buf = [0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut buf).await.unwrap();
    received.lock().unwrap().extend_from_slice(&buf);
    jitter.delay(Point::BeforeData).await;
    sent.lock().unwrap().extend_from_slice(b"hello");
    conn.write_all(b"hello").await.unwrap();
    conn.flush().await.unwrap();

    jitter.delay(Point::BeforeCloseNotify).await;
    conn.get_mut().1.send_close_notify();
    conn.flush().await.unwrap();

    // The next plaintext must be the client's close_notify, not late data.
    jitter.delay(Point::BeforeRead).await;
    let n = conn.read(&mut [0u8; 1]).await.unwrap();
    assert_eq!(
        n, 0,
        "server should receive the client's close_notify without late application data"
    );

    quiet.notify_one();
}

/// Sends `hello` and then closes TCP without a TLS close_notify.
async fn response_then_fin_server(
    socket: Compat<CountingIo<DuplexStream>>,
    sent: Arc<Mutex<Vec<u8>>>,
    received: Arc<Mutex<Vec<u8>>>,
    quiet: Arc<Notify>,
    mut jitter: Jitter,
) {
    let acceptor = TlsAcceptor::from(tls_server_config());
    let mut conn = acceptor.accept(socket).await.unwrap();

    jitter.delay(Point::BeforeRead).await;
    let mut buf = [0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut buf).await.unwrap();
    received.lock().unwrap().extend_from_slice(&buf);
    jitter.delay(Point::BeforeData).await;
    sent.lock().unwrap().extend_from_slice(b"hello");
    conn.write_all(b"hello").await.unwrap();
    conn.flush().await.unwrap();

    quiet.notify_one();
    jitter.delay(Point::BeforeFin).await;
    // Dropping the TLS stream closes the transport without close_notify.
    drop(conn);
}

/// Completes the handshake, reads one record, then stays silent.
async fn silent_server(
    socket: Compat<CountingIo<DuplexStream>>,
    quiet: Arc<Notify>,
    received: Arc<Mutex<Vec<u8>>>,
    expect_close_notify: bool,
    mut jitter: Jitter,
) {
    let acceptor = TlsAcceptor::from(tls_server_config());
    let mut conn = acceptor.accept(socket).await.unwrap();

    jitter.delay(Point::BeforeRead).await;
    let mut buf = [0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut buf).await.unwrap();
    received.lock().unwrap().extend_from_slice(&buf);

    if expect_close_notify {
        jitter.delay(Point::BeforeRead).await;
        let n = conn.read(&mut [0u8; 1]).await.unwrap();
        assert_eq!(n, 0, "server should see a clean close_notify");
    }

    quiet.notify_one();
    std::future::pending::<()>().await;
}

/// Completes the handshake, reads one record, streams several records, waits
/// for the client to read them, then sends `close_notify`.
async fn streaming_server(
    socket: Compat<CountingIo<DuplexStream>>,
    read_done: Arc<Notify>,
    sent: Arc<Mutex<Vec<u8>>>,
    received: Arc<Mutex<Vec<u8>>>,
    expect_close_notify: bool,
    quiet: Arc<Notify>,
    mut jitter: Jitter,
) {
    let acceptor = TlsAcceptor::from(tls_server_config());
    let mut conn = acceptor.accept(socket).await.unwrap();

    jitter.delay(Point::BeforeRead).await;
    let mut buf = [0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut buf).await.unwrap();
    received.lock().unwrap().extend_from_slice(&buf);

    let record = [b'x'; APP_RECORD_LENGTH];
    for _ in 0..STREAM_RECORDS {
        // Space records apart so a client close can land mid-stream.
        jitter.delay(Point::BeforeData).await;
        sent.lock().unwrap().extend_from_slice(&record);
        conn.write_all(&record).await.unwrap();
    }
    conn.flush().await.unwrap();

    read_done.notified().await;

    jitter.delay(Point::BeforeCloseNotify).await;
    conn.get_mut().1.send_close_notify();
    conn.flush().await.unwrap();

    if expect_close_notify {
        jitter.delay(Point::BeforeRead).await;
        let n = conn.read(&mut [0u8; 1]).await.unwrap();
        assert_eq!(n, 0, "server should see a clean close_notify");
    }

    quiet.notify_one();
}

/// Reads once, then closes the raw transport without a TLS close_notify.
fn fin_only_mid_handshake(
    mut socket: CountingIo<DuplexStream>,
    mut jitter: Jitter,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        jitter.delay(Point::BeforeRead).await;
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        jitter.delay(Point::BeforeFin).await;
    })
}

/// Reads the ClientHello, then writes raw bytes and keeps the socket open.
fn raw_after_client_hello(
    mut socket: CountingIo<DuplexStream>,
    bytes: &'static [u8],
    mut jitter: Jitter,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        jitter.delay(Point::BeforeRead).await;
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        jitter.delay(Point::BeforeWrite).await;
        let _ = socket.write_all(bytes).await;
        std::future::pending::<()>().await;
    })
}

fn spawn_server(
    state: State,
    behaviour: Behaviour,
    server_peer: CountingIo<DuplexStream>,
    stream_read: Arc<Notify>,
    sent: Arc<Mutex<Vec<u8>>>,
    quiet: Arc<Notify>,
    received: Arc<Mutex<Vec<u8>>>,
    expect_close_notify: bool,
    close_gate: Option<Arc<Gate>>,
    server_jitter: Jitter,
) -> JoinHandle<()> {
    match (state, behaviour) {
        (State::Connected, Behaviour::CloseNotifyOnly | Behaviour::CloseNotifyOnlyEof) => {
            tokio::spawn(close_notify_only_server(
                server_peer.compat(),
                sent,
                quiet,
                received,
                expect_close_notify,
                close_gate,
                server_jitter,
            ))
        }
        (State::Connected, Behaviour::CloseNotifyThenRejectWrites) => {
            tokio::spawn(close_notify_then_reject_writes_server(
                server_peer.compat(),
                sent,
                received,
                quiet,
                server_jitter,
            ))
        }
        (State::Connected, Behaviour::ResponseThenFin) => tokio::spawn(response_then_fin_server(
            server_peer.compat(),
            sent,
            received,
            quiet,
            server_jitter,
        )),
        (
            State::Connected,
            Behaviour::CloseNotifyThenFin
            | Behaviour::FinOnly
            | Behaviour::FinOnlyNoData
            | Behaviour::FatalAlert
            | Behaviour::CorruptedRecord
            | Behaviour::BadMac,
        ) => tokio::spawn(async move {
            let _ = bind_test_server(server_peer.compat()).await;
        }),
        (State::Connected, Behaviour::Silent) => tokio::spawn(silent_server(
            server_peer.compat(),
            quiet,
            received,
            expect_close_notify,
            server_jitter,
        )),
        (State::Connected, Behaviour::Streaming) => tokio::spawn(streaming_server(
            server_peer.compat(),
            stream_read,
            sent,
            received,
            expect_close_notify,
            quiet,
            server_jitter,
        )),
        (State::MidHandshake, Behaviour::FinOnly) => {
            fin_only_mid_handshake(server_peer, server_jitter)
        }
        (State::MidHandshake, Behaviour::FatalAlert) => {
            raw_after_client_hello(server_peer, FATAL_ALERT, server_jitter)
        }
        (State::MidHandshake, Behaviour::CorruptedRecord) => {
            raw_after_client_hello(server_peer, CORRUPTED_RECORD, server_jitter)
        }
        _ => panic!("unsupported server behaviour for this state"),
    }
}

async fn echo_once(
    conn: &mut tlsn::prover::TlsConnection,
    wrote: &Arc<Mutex<Vec<u8>>>,
    jitter: &mut Jitter,
) -> Vec<u8> {
    let record = pad(b"echo");
    wrote.lock().unwrap().extend_from_slice(&record);
    jitter.delay(Point::BeforeWrite).await;
    conn.write_all(&record).await.unwrap();
    jitter.delay(Point::BeforeRead).await;
    let mut hello = [0u8; 5];
    conn.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    hello.to_vec()
}

async fn client_write(conn: &mut tlsn::prover::TlsConnection, jitter: &mut Jitter, bytes: &[u8]) {
    jitter.delay(Point::BeforeWrite).await;
    conn.write_all(bytes).await.unwrap();
}

fn command_for(behaviour: Behaviour) -> &'static [u8] {
    match behaviour {
        Behaviour::CloseNotifyThenFin => b"send_close_notify_and_close_socket",
        Behaviour::FinOnly => b"close_socket",
        Behaviour::FinOnlyNoData => b"close_socket",
        Behaviour::FatalAlert => b"send_alert",
        Behaviour::CorruptedRecord => b"send_corrupted_message",
        Behaviour::BadMac => b"send_record_with_bad_mac",
        _ => panic!("behaviour has no fixture command"),
    }
}

async fn run(case: Case, plan: &mut Plan) {
    plan.delay("before setup").await;
    let stream_read = Arc::new(Notify::new());
    let sent = Arc::new(Mutex::new(Vec::new()));
    let wrote = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::new(Mutex::new(Vec::new()));
    let server_activity = Arc::new(AtomicUsize::new(0));
    let quiet = Arc::new(Notify::new());
    let expect_close_notify = case.client_close
        || matches!(
            case.behaviour,
            Behaviour::CloseNotifyOnlyEof | Behaviour::CloseNotifyThenRejectWrites
        );
    let close_gate =
        (case.behaviour == Behaviour::CloseNotifyOnly && case.client_close).then(|| {
            let first = if plan.order(RacePoint::CloseNotify, 2) == 0 {
                Party::Server
            } else {
                Party::Client
            };
            Arc::new(Gate::new(first))
        });
    let server_gate = close_gate.clone();
    let mut client_jitter = plan.jitter(Party::Client);
    let server_jitter = plan.jitter(Party::Server);

    let (conn, prover_task, verifier_task, server_task, p_handle, v_handle, p_driver, v_driver) =
        match case.mode {
            Mode::Mpc => {
                let (prover, verifier, p_handle, v_handle, p_task, v_task) =
                    commit_mpc(new_sessions().await).await;
                let (client_io, server_peer) = tokio::io::duplex(TRANSPORT_CAP);
                let server_peer = CountingIo::new(server_peer, server_activity.clone());
                let verifier_task = spawn_verifier_task(plan.jitter(Party::Verifier), async move {
                    verifier.run().await
                });
                let server_task = spawn_server(
                    case.state,
                    case.behaviour,
                    server_peer,
                    stream_read.clone(),
                    sent.clone(),
                    quiet.clone(),
                    received.clone(),
                    expect_close_notify,
                    server_gate,
                    server_jitter,
                );

                let (conn, prover) = prover
                    .connect(tls_client_config(), client_io.compat())
                    .unwrap();
                let prover_task = spawn_prover_task(plan.jitter(Party::Prover), async move {
                    prover.into_future().await
                });
                (
                    conn,
                    prover_task,
                    verifier_task,
                    server_task,
                    p_handle,
                    v_handle,
                    p_task,
                    v_task,
                )
            }
            Mode::Proxy => {
                let (prover, verifier, p_handle, v_handle, p_task, v_task) =
                    commit_proxy(new_sessions().await).await;
                let (server_io, server_peer) = tokio::io::duplex(TRANSPORT_CAP);
                let server_peer = CountingIo::new(server_peer, server_activity.clone());
                let verifier_task = spawn_verifier_task(plan.jitter(Party::Verifier), async move {
                    verifier.run(server_io.compat()).await
                });
                let server_task = spawn_server(
                    case.state,
                    case.behaviour,
                    server_peer,
                    stream_read.clone(),
                    sent.clone(),
                    quiet.clone(),
                    received.clone(),
                    expect_close_notify,
                    server_gate,
                    server_jitter,
                );

                let (conn, prover) = prover.connect(tls_client_config()).unwrap();
                let prover_task = spawn_prover_task(plan.jitter(Party::Prover), async move {
                    prover.into_future().await
                });
                (
                    conn,
                    prover_task,
                    verifier_task,
                    server_task,
                    p_handle,
                    v_handle,
                    p_task,
                    v_task,
                )
            }
        };

    let mut conn = conn;
    let mut client_closed = false;
    let mut prover_task = Some(prover_task);
    let mut verifier_task = Some(verifier_task);

    match (case.state, case.behaviour) {
        (State::MidHandshake, _) => {}
        (State::Connected, Behaviour::Silent) => {
            let record = pad(b"echo");
            wrote.lock().unwrap().extend_from_slice(&record);
            client_write(&mut conn, &mut client_jitter, &record).await;
            if case.client_close {
                close_client(&mut conn, &mut client_closed, &mut client_jitter).await;
            }
        }
        (State::Connected, Behaviour::Streaming) => {
            let record = pad(b"echo");
            wrote.lock().unwrap().extend_from_slice(&record);
            client_write(&mut conn, &mut client_jitter, &record).await;

            if case.client_close {
                // Let the stream start, then half-close while the remaining
                // records are still in flight.
                let mut first = [0u8; 1];
                client_jitter.delay(Point::BeforeRead).await;
                let _ = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut first)).await;
                close_client(&mut conn, &mut client_closed, &mut client_jitter).await;
                // Release the server so it can send close_notify and finish.
                stream_read.notify_one();
            } else {
                let mut app_read = Vec::new();
                let mut buf = [0u8; APP_RECORD_LENGTH];
                while app_read.len() < STREAM_RECORDS * APP_RECORD_LENGTH {
                    client_jitter.delay(Point::BeforeRead).await;
                    match tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => app_read.extend_from_slice(&buf[..n]),
                        Ok(Err(_)) => break,
                        Err(_) => break,
                    }
                }
                stream_read.notify_one();
                assert_eq!(
                    app_read.len(),
                    STREAM_RECORDS * APP_RECORD_LENGTH,
                    "the client should receive the whole stream"
                );
                assert_eq!(
                    app_read.as_slice(),
                    sent.lock().unwrap().as_slice(),
                    "the app must receive every byte the server sent"
                );
            }
        }
        (State::Connected, Behaviour::CloseNotifyOnly | Behaviour::CloseNotifyOnlyEof) => {
            let mut app_read = echo_once(&mut conn, &wrote, &mut client_jitter).await;

            if case.behaviour == Behaviour::CloseNotifyOnlyEof {
                // The server keeps TCP open after close_notify. The prover must
                // still deliver EOF to the application so a reader that waits
                // for it can finish instead of deadlocking.
                let mut rest = Vec::new();
                client_jitter.delay(Point::BeforeRead).await;
                let n = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut rest))
                    .await
                    .expect("app should see EOF after the server close_notify")
                    .expect("the EOF read should not fail");
                assert_eq!(n, 0, "no plaintext should remain after the echo");
                app_read.extend_from_slice(&rest);
            }

            assert_eq!(
                app_read.as_slice(),
                sent.lock().unwrap().as_slice(),
                "the app must receive every byte the server sent"
            );

            if let Some(gate) = close_gate.as_ref() {
                // Enumerated ordering: either the app closes before the server
                // sends close_notify, or it waits for the server to go first.
                let client_first = gate.wait(Party::Client).await;
                close_client(&mut conn, &mut client_closed, &mut client_jitter).await;
                if client_first {
                    gate.open();
                }
            } else if case.client_close || case.behaviour == Behaviour::CloseNotifyOnlyEof {
                close_client(&mut conn, &mut client_closed, &mut client_jitter).await;
            }
        }
        (State::Connected, Behaviour::CloseNotifyThenRejectWrites) => {
            let mut app_read = echo_once(&mut conn, &wrote, &mut client_jitter).await;

            let mut eof = Vec::new();
            client_jitter.delay(Point::BeforeRead).await;
            let n = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut eof))
                .await
                .expect("app should see EOF after the server close_notify")
                .expect("the EOF read should not fail");
            assert_eq!(n, 0, "no plaintext should remain after the echo");
            app_read.extend_from_slice(&eof);
            assert_eq!(
                app_read.as_slice(),
                sent.lock().unwrap().as_slice(),
                "the app must receive every byte the server sent"
            );

            // A write racing with peer closure may be accepted into the local
            // buffer before the prover closes the app-facing pipe. What must
            // hold is that it is never delivered to the server, and that writes
            // fail with BrokenPipe once the pipe is actually closed.
            let late = pad(b"late");
            let err = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    client_jitter.delay(Point::BeforeWrite).await;
                    match conn.write_all(&late).await {
                        Ok(()) => tokio::time::sleep(Duration::from_millis(20)).await,
                        Err(err) => break err,
                    }
                }
            })
            .await
            .expect("late writes should eventually fail once the app pipe closes");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::BrokenPipe,
                "late write should fail with BrokenPipe"
            );

            let _ = conn.close().await;
            client_closed = true;
        }
        (State::Connected, Behaviour::ResponseThenFin) => {
            let record = pad(b"echo");
            wrote.lock().unwrap().extend_from_slice(&record);
            client_write(&mut conn, &mut client_jitter, &record).await;

            let mut response = Vec::new();
            client_jitter.delay(Point::BeforeRead).await;
            let result =
                tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut response))
                    .await
                    .expect("app must terminate after the server FIN");
            // The abrupt close may surface as an error after the buffered
            // plaintext; the data itself must not be lost.
            let _ = result;
            assert_eq!(
                response.as_slice(),
                sent.lock().unwrap().as_slice(),
                "buffered response must reach the app before transport loss"
            );

            client_jitter.delay(Point::BeforeClose).await;
            let _ = conn.close().await;
            client_closed = true;
        }
        (State::Connected, Behaviour::FinOnlyNoData) => {
            client_write(
                &mut conn,
                &mut client_jitter,
                &pad(command_for(case.behaviour)),
            )
            .await;
        }
        (State::Connected, behaviour) => {
            echo_once(&mut conn, &wrote, &mut client_jitter).await;
            client_write(&mut conn, &mut client_jitter, &pad(command_for(behaviour))).await;
        }
    }

    plan.delay("before observation").await;

    let check_app_to_server = case.state == State::Connected
        && matches!(
            case.behaviour,
            Behaviour::Silent
                | Behaviour::Streaming
                | Behaviour::CloseNotifyOnly
                | Behaviour::CloseNotifyOnlyEof
                | Behaviour::CloseNotifyThenRejectWrites
                | Behaviour::ResponseThenFin
        );

    if case.hang.is_none() && check_app_to_server {
        tokio::time::timeout(ROLE_TIMEOUT, quiet.notified())
            .await
            .expect("custom server should reach its quiet point");
        assert_app_to_server(&case, &wrote, &received);
    }

    let (prover_out, verifier_out) = if let Some(cause) = case.hang {
        // Wait until the named peer reaches its terminal quiet point (after
        // the handshake/response, before parking).
        tokio::time::timeout(ROLE_TIMEOUT, quiet.notified())
            .await
            .expect("named peer should reach a quiet point");

        if check_app_to_server {
            assert_app_to_server(&case, &wrote, &received);
        }

        // Let any remaining startup output settle before sampling silence.
        let mut last_activity = server_activity.load(Ordering::Acquire);
        let mut last_sent = sent.lock().unwrap().len();
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let activity = server_activity.load(Ordering::Acquire);
            let sent_len = sent.lock().unwrap().len();
            if activity == last_activity && sent_len == last_sent {
                break;
            }
            last_activity = activity;
            last_sent = sent_len;
        }
        let sent_before = sent.lock().unwrap().len();
        let activity_before = server_activity.load(Ordering::Acquire);
        tokio::time::sleep(ROLE_TIMEOUT).await;

        if case.prover.is_some() {
            assert!(
                !prover_task
                    .as_ref()
                    .expect("expected a prover task")
                    .is_finished(),
                "{}: prover resolved during a legal hang",
                case.name
            );
        }
        if case.verifier.is_some() {
            assert!(
                !verifier_task
                    .as_ref()
                    .expect("expected a verifier task")
                    .is_finished(),
                "{}: verifier resolved during a legal hang",
                case.name
            );
        }
        assert_eq!(
            sent.lock().unwrap().len(),
            sent_before,
            "{}: the named peer must stay idle during a legal hang",
            case.name
        );
        assert_eq!(
            server_activity.load(Ordering::Acquire),
            activity_before,
            "{}: the named peer must produce no output during a legal hang",
            case.name
        );

        assert_hang_is_justified(&case, &server_task, client_closed);
        match cause {
            HangCause::SilentServer => server_task.abort(),
            HangCause::OpenClient => {
                close_client(&mut conn, &mut client_closed, &mut client_jitter).await
            }
            HangCause::OrphanedTransport => {
                panic!("{}: no OrphanedTransport rows here", case.name)
            }
        }

        let (prover_out, verifier_out) = observe_roles(
            if case.prover.is_some() {
                prover_task.take()
            } else {
                None
            },
            if case.verifier.is_some() {
                verifier_task.take()
            } else {
                None
            },
            ROLE_TIMEOUT,
        )
        .await;

        if case.prover == Some(Expect::Hang) {
            let actual = prover_out
                .as_ref()
                .expect("hang row must observe the prover");
            assert!(
                matches!(actual, Outcome::Ok | Outcome::Err(_)),
                "{}: prover still hung after removing {cause:?}: {actual:?}",
                case.name
            );
        }
        if case.verifier == Some(Expect::Hang) {
            let actual = verifier_out
                .as_ref()
                .expect("hang row must observe the verifier");
            assert!(
                matches!(actual, Outcome::Ok | Outcome::Err(_)),
                "{}: verifier still hung after removing {cause:?}: {actual:?}",
                case.name
            );
        }

        // Report the timeout so the outer check still sees a legal hang.
        (
            prover_out.map(|_| Outcome::Timeout),
            verifier_out.map(|_| Outcome::Timeout),
        )
    } else {
        observe_roles(
            if case.prover.is_some() {
                prover_task.take()
            } else {
                None
            },
            if case.verifier.is_some() {
                verifier_task.take()
            } else {
                None
            },
            ROLE_TIMEOUT,
        )
        .await
    };

    if let Some(expected) = case.prover {
        let actual = prover_out.expect("expected a prover outcome");
        check(&case, "prover", expected, actual);
    }
    if let Some(expected) = case.verifier {
        let actual = verifier_out.expect("expected a verifier outcome");
        check(&case, "verifier", expected, actual);
    }

    if let Some(task) = prover_task {
        let mut jitter = plan.jitter(Party::Prover);
        jitter.delay(Point::BeforeAbort).await;
        task.abort();
    }
    if let Some(task) = verifier_task {
        let mut jitter = plan.jitter(Party::Verifier);
        jitter.delay(Point::BeforeAbort).await;
        task.abort();
    }
    let mut server_jitter = plan.jitter(Party::Server);
    server_jitter.delay(Point::BeforeAbort).await;
    server_task.abort();
    p_handle.close();
    v_handle.close();
    p_driver.abort();
    v_driver.abort();
}

/// Asserts that the server received every byte the application wrote.
fn assert_app_to_server(case: &Case, wrote: &Arc<Mutex<Vec<u8>>>, received: &Arc<Mutex<Vec<u8>>>) {
    assert_eq!(
        received.lock().unwrap().as_slice(),
        wrote.lock().unwrap().as_slice(),
        "{}: the server must receive every byte the app wrote",
        case.name
    );
}

async fn close_client(
    conn: &mut tlsn::prover::TlsConnection,
    client_closed: &mut bool,
    jitter: &mut Jitter,
) {
    jitter.delay(Point::BeforeClose).await;
    conn.close().await.unwrap();
    *client_closed = true;
}

/// Asserts that a row's timeout is explained by a live peer.
fn assert_hang_is_justified(case: &Case, server_task: &JoinHandle<()>, client_closed: bool) {
    match case.hang {
        None => {}
        Some(HangCause::SilentServer) => assert!(
            !server_task.is_finished(),
            "{}: a Hang needs a live silent server",
            case.name
        ),
        Some(HangCause::OpenClient) => assert!(
            !client_closed,
            "{}: an OpenClient Hang needs the client to stay open",
            case.name
        ),
        Some(HangCause::OrphanedTransport) => {
            panic!("{}: no OrphanedTransport rows here", case.name)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_behaviour() {
    let stress = Stress::from_env();
    for iteration in 0..stress.repeats() {
        let mut plan = stress.plan(iteration);
        for case in CASES {
            run(*case, &mut plan).await;
        }
    }
}

#[test]
fn case_table_is_well_formed() {
    let mut names = std::collections::HashSet::new();
    let mut keys = std::collections::HashSet::new();
    for case in CASES {
        assert!(names.insert(case.name), "duplicate case: {}", case.name);
        assert!(
            keys.insert((case.mode, case.state, case.behaviour, case.client_close)),
            "duplicate case key for {}",
            case.name
        );
        assert!(
            case.prover.is_some() || case.verifier.is_some(),
            "case has no expected role: {}",
            case.name
        );
        let hangs = matches!(case.prover, Some(Expect::Hang))
            || matches!(case.verifier, Some(Expect::Hang));
        assert_eq!(
            hangs,
            case.hang.is_some(),
            "case must declare a HangCause exactly when it expects a Hang: {}",
            case.name
        );
        if case.hang.is_some() {
            assert!(
                matches!(case.prover, None | Some(Expect::Hang)),
                "hit a HangCause on a non-Hang prover expectation: {}",
                case.name
            );
            assert!(
                matches!(case.verifier, None | Some(Expect::Hang)),
                "hit a HangCause on a non-Hang verifier expectation: {}",
                case.name
            );
        }
        if case.hang == Some(HangCause::OpenClient) {
            assert!(
                !case.client_close,
                "an OpenClient Hang row must not close the client: {}",
                case.name
            );
        }
    }
}
