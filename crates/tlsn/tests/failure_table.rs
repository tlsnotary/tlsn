//! Peer-disappearance failure matrix, in table form.
//!
//! One row per case, each row a short list of steps. A generic runner
//! interprets the steps and asserts the prover/verifier outcomes, so a
//! scenario reads as a sequence of events instead of hand-written plumbing.
//!
//! Each row names its mode and its steps:
//!
//! ```text
//! Mode    Mpc | Proxy
//! Steps   Echo                      one application round-trip
//!         Request                   send the request, don't read the reply
//!         WaitForRequest            wait until the server has read the request
//!         WaitForClientHello        wait until the server has read the ClientHello
//!         WaitForCommitRequest        wait until the verifier has the commit request
//!         CommitInFlight            the commit futures are still running
//!         Lose { actor, loss }      apply a loss trigger to one side
//!         ClientGone                the app client drops without closing
//!         ClientClose               the application client closes its side
//!         ServerGone                no server peer exists at all
//!         ServerOutOfBand(cmd)      the fixture server is driven out of band
//!         Prove | Verify            run the final phase after the session
//! ```
//!
//! Rows are keyed by `(mode, steps)`: two rows with the same pair get the same
//! setup. Phase barriers are explicit steps for exactly this reason, so a row
//! named "mid-handshake" cannot silently collapse into a before-data row.
//! `case_table_is_well_formed` rejects duplicate `(mode, steps)` pairs.
//!
//! Outcomes:
//! - `Ok`/`Err`/`Complete`: the protocol must resolve (no hang, no panic), or
//! - `Hang`: waiting indefinitely is the correct/legal behaviour because the
//!   peer is still alive and the caller is responsible for imposing a timeout.
//!
//! # Coverage
//!
//! The rows form a grid of `mode × actor × phase`; read it that way to find
//! gaps. Phases are, in order:
//!
//! ```text
//! BeforeData     the session is committed, but no TLS byte has been forwarded
//! MidHandshake   the ClientHello is out, the handshake has not completed
//! Echo           one application round-trip has completed
//! ProveVerify    the session finished; the final phase runs
//! ```
//!
//! Pure server termination/fault reactions (`close_notify`, FIN, fatal alert,
//! corrupted record, bad MAC, silent, streaming) are covered by
//! `server_behaviour.rs`. This table owns actor disappearance and ordering;
//! rows that combine a loss with a server close stay here when the ordering is
//! the point.
//!
//! A cell is left empty where the scenario cannot exist or asserts nothing,
//! which is why the grid is sparse rather than complete. The cells someone is
//! most likely to expect and not find are listed here:
//!
//! - `Proxy × VerifierTransport × Echo` is absent because a proxy verifier
//!   owns the server socket during `run()`. Dropping the verifier object while
//!   keeping its transport alive has no separate meaning: the socket goes with
//!   it. `mpc verifier app-object gone, transport alive` covers the case where
//!   the two really are separable.
//!
//! - `ProverOnly` appears only in proxy rows. It exists because proxy mode has
//!   a verifier that reads the server itself, so "the prover is gone and there
//!   is no server" leaves a verifier with something to report. In MPC the
//!   verifier has no server connection of its own, so the same loss is covered
//!   by `mpc prover future gone mid-handshake` and
//!   `mpc prover gone before verify`.
//!
//! - `Mpc × ServerAborted × Echo` as a pure server outcome is covered by
//!   `server_behaviour.rs`. The combined `mpc verifier gone then server closes`
//!   row stays here because the ordering of the two losses is the point.
//!
//! - Proxy rows *do* include `Prove | Verify`. Proxy mode commits to the same
//!   state as MPC and supports the final phase; it was simply untested before
//!   these rows existed.
//!
//! - Ordering of two independent losses is not modelled as an axis. Only two
//!   rows contain more than one loss, so a swap dimension would mostly produce
//!   combinations with nothing to say. A row is added for a specific ordering
//!   only when the ordering itself is the question.

#![allow(unexpected_cfgs)]
#![cfg(tlsn_insecure)]

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[path = "support/counting_io.rs"]
mod counting_io;
#[path = "support/stress.rs"]
mod stress;
use counting_io::CountingIo;
use stress::{Jitter, Party, Plan, Point, Stress};

use futures::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
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
        prove::ProveConfig,
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
    io::{AsyncReadExt as _, DuplexStream},
    task::JoinHandle,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Mode {
    Mpc,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Actor {
    Prover,
    Verifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Loss {
    /// Abort the participant, close its session handle, and abort its driver.
    Composite,
    /// Close only the session handle; participant and driver stay alive.
    HandleClose,
    /// Abort only the session driver; handle and participant stay alive.
    DriverAbort,
    /// Drop only the participant; handle and driver stay alive.
    AppDrop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    /// One application round-trip ("echo" -> "hello").
    Echo,
    /// Send "echo" and read exactly this many bytes of the 5-byte reply.
    ReadReply(usize),
    /// Send "echo" and read this many bytes while the server streams records.
    StreamReply(usize),
    /// The client sends its application request without reading a reply.
    Request,
    /// Wait until the server has read the application request.
    WaitForRequest,
    /// Wait until the server has read the ClientHello.
    WaitForClientHello,
    /// Wait until the verifier has received the commit request.
    WaitForCommitRequest,
    /// The commit futures are running; the next loss happens in the commit
    /// phase rather than after it.
    CommitInFlight,
    /// Apply a loss trigger to one side of the session.
    Lose { actor: Actor, loss: Loss },
    /// The application client closes its side of the TLS connection.
    ClientClose,
    /// The application client drops its transport without closing it.
    ClientGone,
    /// The server is already gone before the scenario starts. Consumed while
    /// building the scenario; applying it is a no-op.
    ServerGone,
    /// The fixture server is driven out of band over the client connection.
    ServerOutOfBand(&'static str),
    /// Run the prover's prove phase after the session completed.
    Prove,
    /// Run the verifier's verify phase after the session completed.
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Ok,
    Err,
    /// Must resolve with either `Ok` or `Err`; must not hang or panic.
    Complete,
    /// Waiting forever is legal because the peer remains alive.
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
    steps: &'static [Step],
    /// Expected outcome for the prover, if the prover future is running.
    prover: Option<Expect>,
    /// Expected outcome for the verifier, if the verifier future is running.
    verifier: Option<Expect>,
    /// Why a hanging role is allowed to wait.
    hang: Option<HangCause>,
}

const fn mpc(
    name: &'static str,
    steps: &'static [Step],
    p: Option<Expect>,
    v: Option<Expect>,
) -> Case {
    Case {
        name,
        mode: Mode::Mpc,
        steps,
        prover: p,
        verifier: v,
        hang: None,
    }
}

const fn proxy(
    name: &'static str,
    steps: &'static [Step],
    p: Option<Expect>,
    v: Option<Expect>,
) -> Case {
    Case {
        name,
        mode: Mode::Proxy,
        steps,
        prover: p,
        verifier: v,
        hang: None,
    }
}

const fn mpc_hang(
    name: &'static str,
    steps: &'static [Step],
    p: Option<Expect>,
    v: Option<Expect>,
    hang: HangCause,
) -> Case {
    Case {
        name,
        mode: Mode::Mpc,
        steps,
        prover: p,
        verifier: v,
        hang: Some(hang),
    }
}

const fn proxy_hang(
    name: &'static str,
    steps: &'static [Step],
    p: Option<Expect>,
    v: Option<Expect>,
    hang: HangCause,
) -> Case {
    Case {
        name,
        mode: Mode::Proxy,
        steps,
        prover: p,
        verifier: v,
        hang: Some(hang),
    }
}

const fn lose(actor: Actor, loss: Loss) -> Step {
    Step::Lose { actor, loss }
}

/// Rows are grouped by how far the session got before anyone disappeared.
const CASES: &[Case] = &[
    // --- Before the session is committed --------------------------------
    // The verifier disappears while the commit futures are in flight.
    mpc(
        "mpc verifier gone during commit",
        &[
            Step::CommitInFlight,
            Step::WaitForCommitRequest,
            lose(Actor::Verifier, Loss::Composite),
        ],
        Some(Expect::Err),
        None,
    ),
    proxy(
        "proxy verifier gone during commit",
        &[
            Step::CommitInFlight,
            Step::WaitForCommitRequest,
            lose(Actor::Verifier, Loss::Composite),
        ],
        Some(Expect::Err),
        None,
    ),
    // The commit completed; the verifier is dropped before the TLS connection.
    proxy(
        "proxy verifier gone before connect",
        &[lose(Actor::Verifier, Loss::Composite)],
        Some(Expect::Err),
        None,
    ),
    // --- Before data ----------------------------------------------------
    // Proxy: both peers are gone before any byte is forwarded.
    //
    // This row was previously labelled "the original verifier `first_read`
    // panic case", but that claim is wrong: the verifier never receives
    // `ProxyFinished` here, so it fails earlier in `wait_finished` with
    // "failed to receive proxy finished message ... unexpected end of file".
    // The `first_read` error ("prover closed before sending any data") is only
    // reachable from a peer that sends `ProxyFinished` without forwarding any
    // proxy bytes, which a well-behaved prover never does. This row still
    // guards that peer loss before data yields an error rather than a panic or
    // a hang.
    proxy(
        "proxy both sides gone before data",
        &[Step::ServerGone, lose(Actor::Prover, Loss::Composite)],
        None,
        Some(Expect::Err),
    ),
    // Proxy: the prover disappears before the ClientHello. This row is
    // deliberately distinct from the mid-handshake row below.
    proxy(
        "proxy prover gone before data",
        &[lose(Actor::Prover, Loss::Composite)],
        None,
        Some(Expect::Err),
    ),
    // MPC: the server is already gone before the prover connects.
    mpc(
        "mpc server gone before handshake",
        &[Step::ServerGone],
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    // --- Mid-handshake --------------------------------------------------
    // Server FIN/alert/corruption mid-handshake is covered by
    // `server_behaviour.rs`; the rows here lose a prover, verifier or client.
    // Proxy: the application client drops after the ClientHello. The server is
    // silent, so both the prover and the verifier wait; that is a legal hang.
    proxy_hang(
        "proxy client EOF mid-handshake",
        &[Step::WaitForClientHello, Step::ClientGone],
        Some(Expect::Hang),
        Some(Expect::Hang),
        HangCause::SilentServer,
    ),
    // MPC: the verifier disappears after the ClientHello, while the server is
    // silent mid-handshake.
    mpc(
        "mpc verifier gone mid-handshake",
        &[
            Step::WaitForClientHello,
            lose(Actor::Verifier, Loss::Composite),
        ],
        Some(Expect::Err),
        None,
    ),
    mpc(
        "mpc prover future gone mid-handshake",
        &[
            Step::WaitForClientHello,
            lose(Actor::Prover, Loss::Composite),
        ],
        None,
        Some(Expect::Err),
    ),
    proxy(
        "proxy verifier gone mid-handshake",
        &[
            Step::WaitForClientHello,
            lose(Actor::Verifier, Loss::Composite),
        ],
        Some(Expect::Err),
        None,
    ),
    proxy(
        "proxy prover gone mid-handshake",
        &[
            Step::WaitForClientHello,
            lose(Actor::Prover, Loss::Composite),
        ],
        None,
        Some(Expect::Err),
    ),
    // The application client disappears after the ClientHello. The server is
    // silent, so both the prover and the verifier wait; that is a legal hang.
    mpc_hang(
        "mpc client gone mid-handshake",
        &[Step::WaitForClientHello, Step::ClientGone],
        Some(Expect::Hang),
        Some(Expect::Hang),
        HangCause::SilentServer,
    ),
    // --- Mid-response ---------------------------------------------------
    // The client has sent its request; the server has read it but has not
    // replied yet. The loss lands after the request is on the wire.
    mpc(
        "mpc verifier gone mid-response",
        &[
            Step::Request,
            Step::WaitForRequest,
            lose(Actor::Verifier, Loss::Composite),
        ],
        Some(Expect::Err),
        None,
    ),
    mpc(
        "mpc prover future gone mid-response",
        &[
            Step::Request,
            Step::WaitForRequest,
            lose(Actor::Prover, Loss::Composite),
        ],
        None,
        Some(Expect::Err),
    ),
    proxy(
        "proxy verifier gone mid-response",
        &[
            Step::Request,
            Step::WaitForRequest,
            lose(Actor::Verifier, Loss::Composite),
        ],
        Some(Expect::Err),
        None,
    ),
    proxy(
        "proxy prover gone mid-response",
        &[
            Step::Request,
            Step::WaitForRequest,
            lose(Actor::Prover, Loss::Composite),
        ],
        None,
        Some(Expect::Err),
    ),
    // --- After the handshake -------------------------------------------
    // Baseline: the client sends its request and both sides close normally.
    // The fixture server is told to send close_notify and shut down, then the
    // client closes; both roles must finalize.
    mpc(
        "mpc client close after handshake",
        &[
            Step::Echo,
            Step::ServerOutOfBand("send_close_notify_and_close_socket"),
            Step::ClientClose,
        ],
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // In proxy mode the fixture shuts down before the client closes without
    // draining, so the prover may observe a broken pipe. Require termination,
    // not success; the clean proxy close is covered by `server_behaviour.rs`.
    proxy(
        "proxy client close after handshake",
        &[
            Step::Echo,
            Step::ServerOutOfBand("send_close_notify_and_close_socket"),
            Step::ClientClose,
        ],
        Some(Expect::Complete),
        Some(Expect::Complete),
    ),
    // Isolated loss triggers. Each mechanism must reach the same closure
    // outcome as the composite rows, so a regression in one path is not hidden
    // by another.
    mpc(
        "mpc verifier driver abort",
        &[Step::Echo, lose(Actor::Verifier, Loss::DriverAbort)],
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    mpc(
        "mpc prover handle close",
        &[Step::Echo, lose(Actor::Prover, Loss::HandleClose)],
        Some(Expect::Err),
        Some(Expect::Err),
    ),
    mpc(
        "mpc verifier gone after handshake",
        &[Step::Echo, lose(Actor::Verifier, Loss::Composite)],
        Some(Expect::Err),
        None,
    ),
    mpc(
        "mpc verifier gone then server closes",
        &[
            Step::Echo,
            lose(Actor::Verifier, Loss::Composite),
            Step::ServerOutOfBand("close_socket"),
        ],
        Some(Expect::Complete),
        None,
    ),
    proxy(
        "proxy verifier gone after handshake",
        &[Step::Echo, lose(Actor::Verifier, Loss::Composite)],
        Some(Expect::Err),
        None,
    ),
    // --- Prove/verify ---------------------------------------------------
    // `prove`/`verify` are the only survivor's role here, so the outcome is
    // recorded on whichever side ran.
    Case {
        name: "mpc verifier gone before prove",
        mode: Mode::Mpc,
        steps: &[lose(Actor::Verifier, Loss::Composite), Step::Prove],
        prover: Some(Expect::Err),
        verifier: None,
        hang: None,
    },
    Case {
        name: "mpc prover gone before verify",
        mode: Mode::Mpc,
        steps: &[lose(Actor::Prover, Loss::Composite), Step::Verify],
        prover: None,
        verifier: Some(Expect::Err),
        hang: None,
    },
    // Proxy commits to the same state as MPC, so prove/verify apply equally.
    Case {
        name: "proxy verifier gone before prove",
        mode: Mode::Proxy,
        steps: &[lose(Actor::Verifier, Loss::Composite), Step::Prove],
        prover: Some(Expect::Err),
        verifier: None,
        hang: None,
    },
    Case {
        name: "proxy prover gone before verify",
        mode: Mode::Proxy,
        steps: &[lose(Actor::Prover, Loss::Composite), Step::Verify],
        prover: None,
        verifier: Some(Expect::Err),
        hang: None,
    },
    // --- Legal waits ----------------------------------------------------
    // Dropping the verifier application object without closing the session
    // does not signal the prover. Waiting is legal; callers must close the
    // transport or impose their own timeout.
    mpc_hang(
        "mpc verifier app-object gone, transport alive",
        &[Step::Echo, lose(Actor::Verifier, Loss::AppDrop)],
        Some(Expect::Hang),
        None,
        HangCause::OrphanedTransport,
    ),
    // The client drops after the handshake. The prover answers the app-side
    // EOF with a TLS close_notify, so the fixture server closes and the
    // session terminates instead of waiting forever.
    mpc(
        "mpc client gone after handshake",
        &[Step::Echo, Step::ClientGone],
        Some(Expect::Complete),
        None,
    ),
    // Proxy counterpart: the client drops without closing after consuming the
    // complete reply. Nothing is left to deliver, so the app-side broken pipe
    // is benign and the prover finalizes.
    proxy(
        "proxy client gone after handshake",
        &[Step::Echo, Step::ClientGone],
        Some(Expect::Ok),
        None,
    ),
    // The app consumed the complete response, the server closed, and then the
    // app dropped. No plaintext remains, so this must not be fatal.
    proxy(
        "proxy client gone after complete response",
        &[
            Step::ReadReply(5),
            Step::ServerOutOfBand("send_close_notify_and_close_socket"),
            Step::ClientGone,
        ],
        Some(Expect::Ok),
        Some(Expect::Ok),
    ),
    // The app drops after reading only part of the response. The remaining
    // plaintext cannot be delivered, so the prover must fail rather than
    // silently discard it.
    proxy(
        "proxy client gone with pending plaintext",
        &[Step::StreamReply(1), Step::ClientGone],
        Some(Expect::Err),
        None,
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
        "{} [{:?} × {:?}] {role}: {actual:?} (expected {expected:?})",
        case.name, case.mode, case.steps
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

async fn observe_ref<T: Send + 'static>(
    task: &mut JoinHandle<tlsn::Result<T>>,
    secs: u64,
) -> Outcome {
    match tokio::time::timeout(Duration::from_secs(secs), &mut *task).await {
        Err(_) => {
            task.abort();
            Outcome::Timeout
        }
        Ok(Err(join)) if join.is_panic() => Outcome::Panic(format!("{:?}", join.into_panic())),
        Ok(Err(join)) => Outcome::Panic(format!("cancelled: {join}")),
        Ok(Ok(Ok(_))) => Outcome::Ok,
        Ok(Ok(Err(err))) => Outcome::Err(err.to_string()),
    }
}

async fn observe<T: Send + 'static>(task: JoinHandle<tlsn::Result<T>>, secs: u64) -> Outcome {
    let mut task = task;
    observe_ref(&mut task, secs).await
}

fn outcome_from_join(res: Result<tlsn::Result<()>, tokio::task::JoinError>) -> Outcome {
    match res {
        Ok(Ok(())) => Outcome::Ok,
        Ok(Err(err)) => Outcome::Err(err.to_string()),
        Err(join) if join.is_panic() => Outcome::Panic(format!("{:?}", join.into_panic())),
        Err(join) => Outcome::Panic(format!("cancelled: {join}")),
    }
}

/// Observes both asserted roles concurrently against a single deadline.
///
/// A role that is still running at the deadline is classified as `Timeout` and
/// aborted together with the other role. Observing sequentially would abort the
/// first hanging participant and could turn the second participant's legal hang
/// into an error.
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

/// Aborts a driver task and surfaces any panic it recorded.
///
/// Drivers are detached behind a wrapper task, so a panic would otherwise be
/// stored in the `JoinHandle` and silently discarded when the handle is
/// aborted or dropped.
async fn abort_driver(role: &str, task: DriverTask) {
    task.abort();
    match task.await {
        Ok(()) => {}
        // Cancellation is the expected outcome of aborting a running driver.
        Err(err) if err.is_cancelled() => {}
        Err(err) => panic!("{role} session driver failed: {err}"),
    }
}

type MpcProver = Prover<tlsn::prover::state::CommitAccepted<tlsn::Mpc>>;
type MpcVerifier = Verifier<tlsn::verifier::state::CommitAccepted<tlsn::Mpc>>;
type ProxyProver = Prover<tlsn::prover::state::CommitAccepted<tlsn::Proxy>>;
type ProxyVerifier = Verifier<tlsn::verifier::state::CommitAccepted<tlsn::Proxy>>;
type CommittedProver = Prover<tlsn::prover::state::Committed>;
type CommittedVerifier = Verifier<tlsn::verifier::state::Committed>;

struct Sessions {
    prover: Prover,
    verifier: Verifier,
    p_handle: SessionHandle,
    v_handle: SessionHandle,
    p_task: DriverTask,
    v_task: DriverTask,
}

async fn sessions_from_sockets<P, V>(p_socket: P, v_socket: V) -> Sessions
where
    P: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    V: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut p_session = Session::new(p_socket);
    let mut v_session = Session::new(v_socket);
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

async fn new_sessions() -> Sessions {
    let (p_io, v_io) = tokio::io::duplex(2 << 23);
    sessions_from_sockets(p_io.compat(), v_io.compat()).await
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

fn tls_config() -> TlsClientConfig {
    TlsClientConfig::builder()
        .root_store(root_store())
        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
        .build()
        .unwrap()
}

fn mpc_config() -> MpcTlsConfig {
    MpcTlsConfig::builder()
        .max_sent_data(1 << 12)
        .max_sent_records(4)
        .max_recv_data(1 << 14)
        .max_recv_records_online(6)
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

const STREAM_RECORDS: usize = 16;

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

/// Reads one request, then streams enough records to leave the prover with
/// undelivered plaintext once the app stops reading.
async fn streaming_server(socket: Compat<CountingIo<DuplexStream>>, mut jitter: Jitter) {
    let acceptor = TlsAcceptor::from(tls_server_config());
    let mut conn = acceptor.accept(socket).await.unwrap();

    jitter.delay(Point::BeforeRead).await;
    let mut buf = [0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut buf).await.unwrap();

    let record = [b'x'; APP_RECORD_LENGTH];
    for _ in 0..STREAM_RECORDS {
        jitter.delay(Point::BeforeData).await;
        // A failing session closes the transport mid-stream. That is the
        // condition under test, not a server-side test failure.
        if conn.write_all(&record).await.is_err() {
            return;
        }
    }
    if conn.flush().await.is_err() {
        return;
    }

    std::future::pending::<()>().await;
}

fn real_server<T>(socket: T) -> JoinHandle<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let _ = bind_test_server(socket.compat()).await;
    })
}

/// Reads once (proving data flowed) then stays connected but silent.
fn silent_server(
    mut socket: CountingIo<DuplexStream>,
    mut jitter: Jitter,
) -> (JoinHandle<()>, tokio::sync::oneshot::Receiver<usize>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        jitter.delay(Point::BeforeRead).await;
        let n = socket.read(&mut buf).await.unwrap_or(0);
        let _ = tx.send(n);
        std::future::pending::<()>().await;
    });
    (task, rx)
}

/// Completes the handshake, reads one application record, reports it and then
/// stays silent, leaving the reply in flight.
async fn read_request_then_silent(
    socket: Compat<CountingIo<DuplexStream>>,
    request_tx: tokio::sync::oneshot::Sender<usize>,
    mut jitter: Jitter,
) {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = RustlsCert::from(SERVER_CERT_DER);
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut conn = acceptor.accept(socket).await.unwrap();

    jitter.delay(Point::BeforeRead).await;
    let mut buf = [0u8; APP_RECORD_LENGTH];
    let n = conn
        .read_exact(&mut buf)
        .await
        .map(|_| buf.len())
        .unwrap_or(0);
    let _ = request_tx.send(n);
    std::future::pending::<()>().await;
}

/// Reads until EOF and then stops; used as a server that closes on EOF.
fn drain_until_eof(mut socket: CountingIo<DuplexStream>, mut jitter: Jitter) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            jitter.delay(Point::BeforeRead).await;
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
}

async fn echo_once(conn: &mut tlsn::prover::TlsConnection) {
    conn.write_all(&pad(b"echo")).await.unwrap();
    let mut hello = [0u8; 5];
    conn.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
}

async fn echo_once_with_jitter(conn: &mut tlsn::prover::TlsConnection, jitter: &mut Jitter) {
    jitter.delay(Point::BeforeWrite).await;
    conn.write_all(&pad(b"echo")).await.unwrap();
    jitter.delay(Point::BeforeRead).await;
    let mut hello = [0u8; 5];
    conn.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
}

async fn client_write(conn: &mut tlsn::prover::TlsConnection, jitter: &mut Jitter, bytes: &[u8]) {
    jitter.delay(Point::BeforeWrite).await;
    conn.write_all(bytes).await.unwrap();
}

/// Runs a participant task with jitter at entry and exit.
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

// ---------------------------------------------------------------------------
// Runner: builds a scenario skeleton from a row, then interprets its steps.
// ---------------------------------------------------------------------------

type ProverTask = JoinHandle<tlsn::Result<()>>;
type VerifierTask = JoinHandle<tlsn::Result<()>>;

/// Live participants a step can touch. Whichever of `prover`/`verifier` is
/// still `Some` when the steps finish is what gets observed.
struct Scenario {
    conn: Option<tlsn::prover::TlsConnection>,
    prover: Option<ProverTask>,
    verifier: Option<VerifierTask>,
    p_handle: Option<SessionHandle>,
    v_handle: Option<SessionHandle>,
    p_driver: Option<DriverTask>,
    v_driver: Option<DriverTask>,
    /// The server peer; `None` means it is already gone.
    server: Option<JoinHandle<()>>,
    /// Fires after the server reads its first bytes, for `WaitForClientHello`.
    server_signal: Option<tokio::sync::oneshot::Receiver<usize>>,
    /// Fires after the server reads the application request.
    request_signal: Option<tokio::sync::oneshot::Receiver<usize>>,
    /// Fires after the verifier has received the commit request.
    commit_signal: Option<tokio::sync::oneshot::Receiver<()>>,
    /// A commit-phase prover future, for rows that lose a peer during commit.
    commit_prover: Option<JoinHandle<tlsn::Result<()>>>,
    /// The verifier's commit future, kept so a commit-phase loss can abort it.
    commit_verifier: Option<JoinHandle<tlsn::Result<()>>>,
    /// Counts server-side write/flush/shutdown activity.
    server_activity: Arc<AtomicUsize>,
    /// The finished session, for post-session rows.
    session: Option<(CommittedProver, CommittedVerifier)>,
    /// Outcome of the prover/verifier after a `Prove`/`Verify` step ran.
    final_prover: Option<Outcome>,
    final_verifier: Option<Outcome>,
}

/// Which skeleton a row needs. This is the only place that has to know about
/// the shape of a scenario; everything after is driven by the step list.
enum Skeleton {
    /// Proxy row where the verifier is closed *before* the prover connects.
    /// The session is committed, but there is no server peer at all.
    BeforeConnect,
    /// The commit futures are running; a later step loses a peer during commit.
    CommitInFlight,
    /// Session committed, client and server connected, handshake undriven.
    Tls,
    /// The whole session is over; prove/verify steps run on the result.
    Finished,
}

impl Skeleton {
    fn for_case(case: &Case) -> Skeleton {
        if case
            .steps
            .iter()
            .any(|s| matches!(s, Step::CommitInFlight | Step::WaitForCommitRequest))
        {
            return Skeleton::CommitInFlight;
        }
        if case
            .steps
            .iter()
            .any(|s| matches!(s, Step::Prove | Step::Verify))
        {
            return Skeleton::Finished;
        }
        if matches!(
            case.steps,
            [Step::Lose {
                actor: Actor::Verifier,
                loss: Loss::Composite,
            }]
        ) {
            return match case.mode {
                // The commit is complete; this row loses the verifier before
                // the TLS connection is made.
                Mode::Proxy => Skeleton::BeforeConnect,
                // A bare MPC verifier loss is still in the commit phase.
                Mode::Mpc => Skeleton::CommitInFlight,
            };
        }
        Skeleton::Tls
    }
}

impl Scenario {
    async fn setup(case: &Case, plan: &Plan) -> Self {
        match Skeleton::for_case(case) {
            Skeleton::CommitInFlight => {
                let Sessions {
                    prover,
                    verifier,
                    p_handle,
                    v_handle,
                    p_task,
                    v_task,
                } = new_sessions().await;
                let mode = case.mode;
                let (commit_tx, commit_signal) = tokio::sync::oneshot::channel();
                // Rows that use this skeleton lose the verifier while the
                // commit is in flight. Hold `accept()` until that happens so
                // the phase cannot advance underneath the loss step.
                let verifier_gate = Arc::new(tokio::sync::Notify::new());

                let commit_prover = spawn_prover_task(plan.jitter(Party::Prover), async move {
                    match mode {
                        Mode::Mpc => prover.commit(mpc_config()).await.map(drop),
                        Mode::Proxy => prover.commit(proxy_config()).await.map(drop),
                    }
                });
                let commit_verifier =
                    spawn_verifier_task(plan.jitter(Party::Verifier), async move {
                        let start = match verifier.commit().await {
                            Ok(start) => start,
                            Err(err) => {
                                let _ = commit_tx.send(());
                                return Err(err);
                            }
                        };
                        // `commit()` has consumed the prover's commit request.
                        let _ = commit_tx.send(());
                        verifier_gate.notified().await;
                        match start {
                            VerifierCommitStart::Mpc(verifier) => verifier.accept().await.map(drop),
                            VerifierCommitStart::Proxy(verifier) => {
                                verifier.accept().await.map(drop)
                            }
                        }
                    });

                // Let both commit futures start before the row's loss step runs.
                tokio::task::yield_now().await;

                Scenario {
                    conn: None,
                    prover: None,
                    verifier: None,
                    p_handle: Some(p_handle),
                    v_handle: Some(v_handle),
                    p_driver: Some(p_task),
                    v_driver: Some(v_task),
                    server_activity: Arc::new(AtomicUsize::new(0)),
                    server: None,
                    server_signal: None,
                    request_signal: None,
                    commit_signal: Some(commit_signal),
                    commit_prover: Some(commit_prover),
                    commit_verifier: Some(commit_verifier),
                    session: None,
                    final_prover: None,
                    final_verifier: None,
                }
            }
            Skeleton::BeforeConnect => {
                let (prover, verifier, p_handle, v_handle, p_task, v_task) =
                    commit_proxy(new_sessions().await).await;
                drop(verifier);
                v_handle.close();
                // Keep the aborted handle so `run` can check it for panics.
                v_task.abort();
                drop(v_handle);

                let (_conn, prover) = prover.connect(tls_config()).unwrap();
                let prover_task = spawn_prover_task(plan.jitter(Party::Prover), async move {
                    prover.into_future().await
                });
                Scenario {
                    conn: None,
                    prover: Some(prover_task),
                    // Nobody to serve the prover.
                    verifier: None,
                    p_handle: Some(p_handle),
                    v_handle: None,
                    p_driver: Some(p_task),
                    v_driver: Some(v_task),
                    server_activity: Arc::new(AtomicUsize::new(0)),
                    server: None,
                    server_signal: None,
                    request_signal: None,
                    commit_signal: None,
                    commit_prover: None,
                    commit_verifier: None,
                    session: None,
                    final_prover: None,
                    final_verifier: None,
                }
            }
            Skeleton::Finished => {
                let (prover, verifier, p_handle, v_handle, p_task, v_task, server) = match case.mode
                {
                    Mode::Mpc => complete_mpc().await,
                    Mode::Proxy => complete_proxy().await,
                };
                Scenario {
                    conn: None,
                    prover: None,
                    verifier: None,
                    p_handle: Some(p_handle),
                    v_handle: Some(v_handle),
                    p_driver: Some(p_task),
                    v_driver: Some(v_task),
                    server_activity: Arc::new(AtomicUsize::new(0)),
                    server: Some(server),
                    server_signal: None,
                    request_signal: None,
                    commit_signal: None,
                    commit_prover: None,
                    commit_verifier: None,
                    session: Some((prover, verifier)),
                    final_prover: None,
                    final_verifier: None,
                }
            }
            Skeleton::Tls => Scenario::tls(case, plan).await,
        }
    }

    async fn tls(case: &Case, plan: &Plan) -> Self {
        let (prover, verifier, p_handle, v_handle, p_task, v_task) = match case.mode {
            Mode::Mpc => {
                let (p, v, ph, vh, pt, vt) = commit_mpc(new_sessions().await).await;
                (TlsProver::Mpc(p), TlsVerifier::Mpc(v), ph, vh, pt, vt)
            }
            Mode::Proxy => {
                let (p, v, ph, vh, pt, vt) = commit_proxy(new_sessions().await).await;
                (TlsProver::Proxy(p), TlsVerifier::Proxy(v), ph, vh, pt, vt)
            }
        };

        let (client_io, server_io) = tokio::io::duplex(2 << 16);

        // The verifier consumes the server socket in proxy mode; the server
        // peer is the other end of the same duplex in both modes.
        let (verifier_task, server_peer) = match verifier {
            TlsVerifier::Mpc(v) => (
                spawn_verifier_task(plan.jitter(Party::Verifier), async move { v.run().await }),
                server_io,
            ),
            TlsVerifier::Proxy(v) => {
                let (server_io, server_peer) = tokio::io::duplex(2 << 16);
                (
                    spawn_verifier_task(plan.jitter(Party::Verifier), async move {
                        v.run(server_io.compat()).await
                    }),
                    server_peer,
                )
            }
        };

        let server_activity = Arc::new(AtomicUsize::new(0));
        let server_peer = CountingIo::new(server_peer, server_activity.clone());

        // What the server peer does, given the row. The first receiver fires
        // after the server reads the ClientHello; the second after it reads the
        // application request.
        let (server, server_signal, request_signal): (
            Option<JoinHandle<()>>,
            Option<tokio::sync::oneshot::Receiver<usize>>,
            Option<tokio::sync::oneshot::Receiver<usize>>,
        ) = match case.steps {
            // The server is gone before anything starts.
            [Step::ServerGone, ..] => {
                drop(server_peer);
                (None, None, None)
            }
            // Mid-response: the server reads the request and then stays silent.
            [Step::Request, ..] => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                (
                    Some(tokio::spawn(read_request_then_silent(
                        server_peer.compat(),
                        tx,
                        plan.jitter(Party::Server),
                    ))),
                    None,
                    Some(rx),
                )
            }
            [Step::StreamReply(_), ..] => (
                Some(tokio::spawn(streaming_server(
                    server_peer.compat(),
                    plan.jitter(Party::Server),
                ))),
                None,
                None,
            ),
            [Step::Echo, ..] | [Step::ReadReply(_), ..] => {
                (Some(real_server(server_peer)), None, None)
            }
            // Proxy before-data: a server that serves normally and closes
            // when the prover goes away.
            [
                Step::Lose {
                    actor: Actor::Prover,
                    ..
                },
                ..,
            ] if case.mode == Mode::Proxy => (
                Some(drain_until_eof(server_peer, plan.jitter(Party::Server))),
                None,
                None,
            ),
            // Everything else gets a server that reads the ClientHello and
            // then stays silent; `WaitForClientHello` waits on the receiver.
            _ => {
                let (task, rx) = silent_server(server_peer, plan.jitter(Party::Server));
                (Some(task), Some(rx), None)
            }
        };

        let (conn, prover_task) =
            match prover {
                TlsProver::Mpc(p) => {
                    let (conn, p) = p.connect(tls_config(), client_io.compat()).unwrap();
                    (
                        conn,
                        spawn_prover_task(plan.jitter(Party::Prover), async move {
                            p.into_future().await
                        }),
                    )
                }
                TlsProver::Proxy(p) => {
                    let (conn, p) = p.connect(tls_config()).unwrap();
                    (
                        conn,
                        spawn_prover_task(plan.jitter(Party::Prover), async move {
                            p.into_future().await
                        }),
                    )
                }
            };

        Scenario {
            conn: Some(conn),
            prover: Some(prover_task),
            verifier: Some(verifier_task),
            p_handle: Some(p_handle),
            v_handle: Some(v_handle),
            p_driver: Some(p_task),
            v_driver: Some(v_task),
            server_activity,
            server,
            server_signal,
            request_signal,
            commit_signal: None,
            commit_prover: None,
            commit_verifier: None,
            session: None,
            final_prover: None,
            final_verifier: None,
        }
    }

    async fn apply_step(&mut self, step: Step, plan: &Plan, client_jitter: &mut Jitter) {
        match step {
            Step::Echo => {
                let conn = self.conn.as_mut().expect("Echo needs a live client conn");
                echo_once_with_jitter(conn, client_jitter).await;
            }
            Step::ReadReply(n) => {
                let conn = self
                    .conn
                    .as_mut()
                    .expect("ReadReply needs a live client conn");
                assert!(n <= 5, "the fixture reply is 5 bytes");
                client_jitter.delay(Point::BeforeWrite).await;
                conn.write_all(&pad(b"echo")).await.unwrap();
                if n > 0 {
                    client_jitter.delay(Point::BeforeRead).await;
                    let mut reply = vec![0u8; n];
                    conn.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply, &b"hello"[..n]);
                }
            }
            Step::StreamReply(n) => {
                let conn = self
                    .conn
                    .as_mut()
                    .expect("StreamReply needs a live client conn");
                client_jitter.delay(Point::BeforeWrite).await;
                conn.write_all(&pad(b"echo")).await.unwrap();
                if n > 0 {
                    client_jitter.delay(Point::BeforeRead).await;
                    let mut reply = vec![0u8; n];
                    conn.read_exact(&mut reply).await.unwrap();
                }
            }
            Step::Request => {
                let conn = self
                    .conn
                    .as_mut()
                    .expect("Request needs a live client conn");
                client_write(conn, client_jitter, &pad(b"request")).await;
            }
            Step::WaitForRequest => {
                let rx = self
                    .request_signal
                    .take()
                    .expect("WaitForRequest needs a server that reads the request");
                let n = tokio::time::timeout(Duration::from_secs(10), rx)
                    .await
                    .expect("server should read the request")
                    .expect("server read task should signal");
                assert!(n > 0, "the request should be non-empty");
            }
            Step::WaitForClientHello => {
                let rx = self
                    .server_signal
                    .take()
                    .expect("WaitForClientHello needs a server that reads");
                let n = tokio::time::timeout(Duration::from_secs(10), rx)
                    .await
                    .expect("server should read the ClientHello")
                    .expect("server read task should signal");
                assert!(n > 0, "the ClientHello should be non-empty");
            }
            Step::WaitForCommitRequest => {
                let rx = self
                    .commit_signal
                    .take()
                    .expect("WaitForCommitRequest needs a commit-phase session");
                tokio::time::timeout(Duration::from_secs(10), rx)
                    .await
                    .expect("the verifier should receive the commit request")
                    .expect("the commit verifier should signal");
            }
            Step::CommitInFlight => {
                tokio::task::yield_now().await;
            }
            Step::ClientClose => {
                // A normal close ends with the application handle gone, not
                // merely half-closed.
                let mut conn = self.conn.take().expect("ClientClose needs a live conn");
                client_jitter.delay(Point::BeforeClose).await;
                conn.close().await.unwrap();
            }
            Step::Lose { actor, loss } => self.lose(actor, loss),
            Step::ClientGone => {
                client_jitter.delay(Point::BeforeClientDrop).await;
                self.conn = None;
            }
            Step::ServerGone => {}
            Step::ServerOutOfBand(cmd) => {
                let conn = self.conn.as_mut().expect("needs a live conn");
                client_jitter.delay(Point::BeforeWrite).await;
                // A prior loss may already have torn down the connection. This
                // is a control write, not the row's assertion: the expected
                // prover/verifier outcome still has to hold.
                let _ = conn.write_all(&pad(cmd.as_bytes())).await;
            }
            Step::Prove => {
                let (mut prover, _) = self.session.take().expect("Prove needs a session");
                let config = ProveConfig::builder(prover.transcript()).build().unwrap();
                let task = spawn_prover_task(plan.jitter(Party::Prover), async move {
                    prover.prove(&config).await
                });
                self.final_prover = Some(observe(task, 5).await);
            }
            Step::Verify => {
                let (_, verifier) = self.session.take().expect("Verify needs a session");
                let task = spawn_verifier_task(plan.jitter(Party::Verifier), async move {
                    verifier.verify().await
                });
                self.final_verifier = Some(observe(task, 5).await);
            }
        }
    }

    fn lose(&mut self, actor: Actor, loss: Loss) {
        match (actor, loss) {
            // Composite: the participant disappears together with its session.
            (Actor::Prover, Loss::Composite) => {
                if let Some(task) = self.commit_prover.take() {
                    task.abort();
                }
                if let Some(task) = self.prover.take() {
                    task.abort();
                }
                if let Some(handle) = self.p_handle.take() {
                    handle.close();
                }
                if let Some(task) = self.p_driver.as_ref() {
                    task.abort();
                }
            }
            (Actor::Verifier, Loss::Composite) => {
                if let Some(task) = self.commit_verifier.take() {
                    task.abort();
                }
                if let Some(task) = self.verifier.take() {
                    task.abort();
                }
                if let Some(handle) = self.v_handle.take() {
                    handle.close();
                }
                if let Some(task) = self.v_driver.as_ref() {
                    task.abort();
                }
            }
            // Graceful close only: the driver keeps polling and the participant
            // stays alive, exercising the handle -> driver path.
            (Actor::Prover, Loss::HandleClose) => {
                if let Some(handle) = self.p_handle.take() {
                    handle.close();
                }
            }
            (Actor::Verifier, Loss::HandleClose) => {
                if let Some(handle) = self.v_handle.take() {
                    handle.close();
                }
            }
            // Driver abort only: the participant must learn through the
            // driver's Drop impl.
            (Actor::Prover, Loss::DriverAbort) => {
                if let Some(task) = self.p_driver.as_ref() {
                    task.abort();
                }
            }
            (Actor::Verifier, Loss::DriverAbort) => {
                if let Some(task) = self.v_driver.as_ref() {
                    task.abort();
                }
            }
            // Participant drop only: the session and transport stay alive, so
            // nothing should signal closure.
            (Actor::Prover, Loss::AppDrop) => {
                if let Some(task) = self.commit_prover.take() {
                    task.abort();
                }
                if let Some(task) = self.prover.take() {
                    task.abort();
                }
            }
            (Actor::Verifier, Loss::AppDrop) => {
                if let Some(task) = self.commit_verifier.take() {
                    task.abort();
                }
                if let Some(task) = self.verifier.take() {
                    task.abort();
                }
            }
        }
    }

    /// Runs the row's steps, then observes whatever is still alive.
    async fn run(mut self, case: &Case, plan: &mut Plan) -> (Option<Outcome>, Option<Outcome>) {
        // Do not delay between steps: phase assertions such as "verifier gone
        // during commit" require the loss to happen before the phase advances.
        // Per-party delays belong inside the actors, not in the orchestrator.
        let mut client_jitter = plan.jitter(Party::Client);
        for step in case.steps {
            self.apply_step(*step, plan, &mut client_jitter).await;
        }
        plan.delay("before observation").await;

        let (prover_done, prover_task) = if case.prover.is_some() {
            match (
                self.final_prover.take(),
                self.prover.take(),
                self.commit_prover.take(),
            ) {
                (Some(done), _, _) => (Some(done), None),
                (None, Some(task), _) => (None, Some(task)),
                (None, None, Some(task)) => (None, Some(task)),
                _ => (None, None),
            }
        } else {
            (None, None)
        };
        let (verifier_done, verifier_task) = if case.verifier.is_some() {
            match (self.final_verifier.take(), self.verifier.take()) {
                (Some(done), _) => (Some(done), None),
                (None, Some(task)) => (None, Some(task)),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        let (prover, verifier) = if let Some(cause) = case.hang {
            self.run_hang_probe(
                case,
                prover_done,
                verifier_done,
                prover_task,
                verifier_task,
                cause,
            )
            .await
        } else {
            let (prover_out, verifier_out) =
                observe_roles(prover_task, verifier_task, Duration::from_secs(5)).await;
            (prover_done.or(prover_out), verifier_done.or(verifier_out))
        };

        if let Some(handle) = self.p_handle.take() {
            handle.close();
        }
        if let Some(handle) = self.v_handle.take() {
            handle.close();
        }
        if let Some(task) = self.p_driver.take() {
            let mut jitter = plan.jitter(Party::Prover);
            jitter.delay(Point::BeforeAbort).await;
            abort_driver("prover", task).await;
        }
        if let Some(task) = self.v_driver.take() {
            let mut jitter = plan.jitter(Party::Verifier);
            jitter.delay(Point::BeforeAbort).await;
            abort_driver("verifier", task).await;
        }
        if let Some(task) = self.server.take() {
            let mut jitter = plan.jitter(Party::Server);
            jitter.delay(Point::BeforeAbort).await;
            task.abort();
        }
        if let Some(task) = self.commit_prover.take() {
            let mut jitter = plan.jitter(Party::Prover);
            jitter.delay(Point::BeforeAbort).await;
            task.abort();
        }
        if let Some(task) = self.commit_verifier.take() {
            let mut jitter = plan.jitter(Party::Verifier);
            jitter.delay(Point::BeforeAbort).await;
            task.abort();
        }

        (prover, verifier)
    }

    /// Proves that a legal hang is caused by the named live peer.
    ///
    /// Waits without aborting the participants, checks they are still pending,
    /// removes the peer whose silence justifies the wait, and then requires
    /// every hanging role to resolve. A hang caused by anything else stays
    /// pending and fails the row.
    #[allow(clippy::too_many_arguments)]
    async fn run_hang_probe(
        &mut self,
        case: &Case,
        prover_done: Option<Outcome>,
        verifier_done: Option<Outcome>,
        prover_task: Option<ProverTask>,
        verifier_task: Option<VerifierTask>,
        cause: HangCause,
    ) -> (Option<Outcome>, Option<Outcome>) {
        // Let any startup handshake output settle before sampling silence.
        let mut last_activity = self.server_activity.load(Ordering::Acquire);
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let now = self.server_activity.load(Ordering::Acquire);
            if now == last_activity {
                break;
            }
            last_activity = now;
        }
        let activity_before = self.server_activity.load(Ordering::Acquire);
        tokio::time::sleep(Duration::from_secs(5)).await;

        if let Some(outcome) = prover_done {
            panic!(
                "{}: prover resolved during a legal hang: {outcome:?}",
                case.name
            );
        }
        if let Some(outcome) = verifier_done {
            panic!(
                "{}: verifier resolved during a legal hang: {outcome:?}",
                case.name
            );
        }
        assert!(
            prover_task.as_ref().is_none_or(|task| !task.is_finished()),
            "{}: prover resolved during a legal hang",
            case.name
        );
        assert!(
            verifier_task
                .as_ref()
                .is_none_or(|task| !task.is_finished()),
            "{}: verifier resolved during a legal hang",
            case.name
        );

        assert_eq!(
            self.server_activity.load(Ordering::Acquire),
            activity_before,
            "{}: the named peer must stay idle during a legal hang",
            case.name
        );

        self.assert_hang_is_justified(cause);
        self.remove_hang_peer(cause).await;

        let (prover_out, verifier_out) =
            observe_roles(prover_task, verifier_task, Duration::from_secs(5)).await;

        let prover = match case.prover {
            Some(Expect::Hang) => {
                let outcome = prover_out.expect("hang row must observe the prover");
                assert!(
                    matches!(outcome, Outcome::Ok | Outcome::Err(_)),
                    "{}: prover still hung after removing {cause:?}: {outcome:?}",
                    case.name
                );
                // The outer check still sees the row as a legal hang.
                Some(Outcome::Timeout)
            }
            Some(_) => panic!("{}: HangCause requires a Hang expectation", case.name),
            None => None,
        };
        let verifier = match case.verifier {
            Some(Expect::Hang) => {
                let outcome = verifier_out.expect("hang row must observe the verifier");
                assert!(
                    matches!(outcome, Outcome::Ok | Outcome::Err(_)),
                    "{}: verifier still hung after removing {cause:?}: {outcome:?}",
                    case.name
                );
                Some(Outcome::Timeout)
            }
            Some(_) => panic!("{}: HangCause requires a Hang expectation", case.name),
            None => None,
        };

        (prover, verifier)
    }

    /// Removes the peer named by a hang cause.
    async fn remove_hang_peer(&mut self, cause: HangCause) {
        match cause {
            HangCause::SilentServer => {
                if let Some(task) = self.server.as_ref() {
                    task.abort();
                }
            }
            HangCause::OpenClient => {
                if let Some(mut conn) = self.conn.take() {
                    let _ = conn.close().await;
                }
            }
            HangCause::OrphanedTransport => {
                // The row currently models an orphaned verifier transport.
                if let Some(task) = self.v_driver.as_ref() {
                    task.abort();
                } else if let Some(task) = self.p_driver.as_ref() {
                    task.abort();
                }
            }
        }
    }

    /// Asserts that a row's timeout is explained by a live peer.
    fn assert_hang_is_justified(&self, cause: HangCause) {
        match cause {
            HangCause::SilentServer => assert!(
                self.server.as_ref().is_some_and(|task| !task.is_finished()),
                "a Hang needs a live silent server"
            ),
            HangCause::OpenClient => {
                assert!(self.conn.is_some(), "a Hang needs a live open client")
            }
            HangCause::OrphanedTransport => assert!(
                self.p_driver
                    .as_ref()
                    .is_some_and(|task| !task.is_finished())
                    || self
                        .v_driver
                        .as_ref()
                        .is_some_and(|task| !task.is_finished()),
                "a Hang needs a live orphaned transport"
            ),
        }
    }
}

enum TlsProver {
    Mpc(MpcProver),
    Proxy(ProxyProver),
}

enum TlsVerifier {
    Mpc(MpcVerifier),
    Proxy(ProxyVerifier),
}

/// Completes a full MPC session: handshake, one app round-trip, clean
/// close_notify + socket close on both sides.
async fn complete_mpc() -> (
    CommittedProver,
    CommittedVerifier,
    SessionHandle,
    SessionHandle,
    DriverTask,
    DriverTask,
    JoinHandle<()>,
) {
    let Sessions {
        prover,
        verifier,
        p_handle,
        v_handle,
        p_task,
        v_task,
    } = new_sessions().await;

    let (prover, verifier) = tokio::join!(prover.commit(mpc_config()), async {
        let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
            panic!("wrong mode")
        };
        verifier.accept().await.unwrap()
    });
    let prover = prover.unwrap();

    let (client_io, server_io) = tokio::io::duplex(2 << 16);
    let server_task = real_server(server_io);
    let verifier_task = tokio::spawn(async move { verifier.run().await });

    let (mut conn, prover) = prover.connect(tls_config(), client_io.compat()).unwrap();
    let prover_task = tokio::spawn(async move { prover.into_future().await });
    echo_once(&mut conn).await;

    conn.write_all(&pad(b"send_close_notify_and_close_socket"))
        .await
        .unwrap();
    conn.close().await.unwrap();
    let mut drain = Vec::new();
    let _ = conn.read_to_end(&mut drain).await;

    let prover = prover_task.await.unwrap().unwrap();
    let verifier = verifier_task.await.unwrap().unwrap();

    (
        prover,
        verifier,
        p_handle,
        v_handle,
        p_task,
        v_task,
        server_task,
    )
}

/// Completes a full proxy session: handshake, one app round-trip, clean
/// close_notify + socket close on both sides.
#[allow(clippy::type_complexity)]
async fn complete_proxy() -> (
    CommittedProver,
    CommittedVerifier,
    SessionHandle,
    SessionHandle,
    DriverTask,
    DriverTask,
    JoinHandle<()>,
) {
    let Sessions {
        prover,
        verifier,
        p_handle,
        v_handle,
        p_task,
        v_task,
    } = new_sessions().await;

    let (prover, verifier) = tokio::join!(prover.commit(proxy_config()), async {
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await.unwrap() else {
            panic!("wrong mode")
        };
        verifier.accept().await.unwrap()
    });
    let prover = prover.unwrap();

    // The proxy verifier dials the server itself.
    let (server_io, server_peer) = tokio::io::duplex(2 << 16);
    let server_task = real_server(server_peer);
    let verifier_task = tokio::spawn(async move { verifier.run(server_io.compat()).await });

    let (mut conn, prover) = prover.connect(tls_config()).unwrap();
    let prover_task = tokio::spawn(async move { prover.into_future().await });
    echo_once(&mut conn).await;

    conn.write_all(&pad(b"send_close_notify_and_close_socket"))
        .await
        .unwrap();
    conn.close().await.unwrap();
    let mut drain = Vec::new();
    let _ = conn.read_to_end(&mut drain).await;

    let prover = prover_task.await.unwrap().unwrap();
    let verifier = verifier_task.await.unwrap().unwrap();

    (
        prover,
        verifier,
        p_handle,
        v_handle,
        p_task,
        v_task,
        server_task,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Runs every row of the failure table sequentially.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failure_table() {
    let stress = Stress::from_env();
    for iteration in 0..stress.repeats() {
        let mut plan = stress.plan(iteration);
        for case in CASES {
            let scenario = Scenario::setup(case, &plan).await;
            let (prover, verifier) = scenario.run(case, &mut plan).await;
            if let Some(expected) = case.prover {
                let actual = prover.unwrap_or_else(|| {
                    panic!(
                        "{} (iteration {iteration}): expected a prover outcome, but none was produced",
                        case.name
                    )
                });
                check(case, "prover", expected, actual);
            }
            if let Some(expected) = case.verifier {
                let actual = verifier.unwrap_or_else(|| {
                    panic!(
                        "{} (iteration {iteration}): expected a verifier outcome, but none was produced",
                        case.name
                    )
                });
                check(case, "verifier", expected, actual);
            }
        }
    }
}

/// Verifies the table has unique case names, unique `(mode, steps)` scenarios,
/// and every case has at least one expected role.
#[test]
fn case_table_is_well_formed() {
    let mut names = std::collections::HashSet::new();
    let mut scenarios = std::collections::HashSet::new();
    for case in CASES {
        assert!(names.insert(case.name), "duplicate case: {}", case.name);
        assert!(
            scenarios.insert((case.mode, case.steps)),
            "duplicate scenario for {}: {:?} × {:?}",
            case.name,
            case.mode,
            case.steps
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
    }
}
