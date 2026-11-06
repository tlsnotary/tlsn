//! Regression: a session closing after the TLS output exists must not turn the
//! prover's successful connection phase into an error.
//!
//! `Prover::poll` used to check the session closure before checking whether the
//! TLS output was ready. If the output was already produced but closing the
//! transport was still pending, a session that closed before the next poll made
//! the prover report "session closed while the prover was connected".
//!
//! The test makes the final transport close block, waits until the prover has
//! produced its output and closed the application side of the TLS connection,
//! then closes the session and releases the transport close. The prover must
//! not surface the stale session-closed error.
//!
//! This needs `tlsn_insecure` so the MPC setup is cheap. Run it with:
//!
//! ```text
//! RUSTFLAGS="--cfg tlsn_insecure" \
//!     cargo test -p tlsn --test prover_close_after_output --profile tests-integration
//! ```

#![allow(unexpected_cfgs)]
#![cfg(tlsn_insecure)]

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tls_server_fixture::{APP_RECORD_LENGTH, CA_CERT_DER, SERVER_DOMAIN, bind_test_server};
use tlsn::{
    Session,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::ServerName,
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tokio_util::compat::TokioAsyncReadCompatExt;

const TIMEOUT: Duration = Duration::from_secs(60);

/// Gate controlling whether the transport may finish closing.
#[derive(Default)]
struct CloseGate {
    open: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

impl CloseGate {
    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        let wakers: Vec<Waker> = self.wakers.lock().unwrap().drain(..).collect();
        for waker in wakers {
            waker.wake();
        }
    }
}

/// A socket whose `poll_close` stays pending until the gate opens.
///
/// Reads and writes are delegated unchanged, so the TLS handshake and traffic
/// proceed normally; only the final close is held back.
struct GatedClose<S> {
    inner: S,
    gate: Arc<CloseGate>,
}

impl<S> AsyncRead for GatedClose<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for GatedClose<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut wakers = self.gate.wakers.lock().unwrap();
            if !self.gate.open.load(Ordering::SeqCst) {
                if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
                    wakers.push(cx.waker().clone());
                }
                return Poll::Pending;
            }
        }

        Pin::new(&mut self.inner).poll_close(cx)
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

fn mpc_config() -> MpcTlsConfig {
    MpcTlsConfig::builder()
        .max_sent_data(1 << 12)
        .max_sent_records(4)
        .max_recv_data(1 << 14)
        .max_recv_records_online(6)
        .build()
        .unwrap()
}

/// Pads a command to a full record, as expected by the raw test server.
fn pad_record(command: &[u8]) -> Vec<u8> {
    let mut record = command.to_vec();
    record.resize(APP_RECORD_LENGTH, 0);
    record
}

/// Tracks whether a poll of the prover future is currently in progress.
struct Observed<F> {
    inner: Pin<Box<F>>,
    in_poll: Arc<AtomicUsize>,
}

impl<F: Future> Future for Observed<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        this.in_poll.fetch_add(1, Ordering::SeqCst);
        let poll = this.inner.as_mut().poll(cx);
        this.in_poll.fetch_sub(1, Ordering::SeqCst);
        poll
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_close_after_output_is_not_reported_as_an_error() {
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

    let (p_driver, _p_handle) = p_session.split();
    let (v_driver, _v_handle) = v_session.split();
    let p_driver = tokio::spawn(p_driver);
    let v_driver = tokio::spawn(v_driver);

    let (prover, verifier) = tokio::join!(prover.commit(mpc_config()), async {
        let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
            panic!("expected MPC commit protocol");
        };
        verifier.accept().await.unwrap()
    });
    let prover = prover.unwrap();

    let verifier_task = tokio::spawn(async move { verifier.run().await });

    let (client_socket, server_socket) = tokio::io::duplex(2 << 20);
    let server_task = tokio::spawn(bind_test_server(server_socket.compat()));

    let gate = Arc::new(CloseGate::default());
    let prover_socket = GatedClose {
        inner: client_socket.compat(),
        gate: gate.clone(),
    };

    let (mut conn, prover) = prover.connect(tls_client_config(), prover_socket).unwrap();
    let in_poll = Arc::new(AtomicUsize::new(0));
    let prover_task = tokio::spawn(Observed {
        inner: Box::pin(prover.into_future()),
        in_poll: in_poll.clone(),
    });

    conn.write_all(&pad_record(b"send_close_notify_and_close_socket"))
        .await
        .unwrap();

    // The application side sees EOF only after the prover has produced the TLS
    // output and closed `client_io`. At that point the final transport close is
    // still blocked in `poll_close`, which is exactly the window the regression
    // is about.
    let mut response = Vec::new();
    tokio::time::timeout(TIMEOUT, conn.read_to_end(&mut response))
        .await
        .expect("application side should observe EOF once the output is ready")
        .expect("reading from the TLS connection should succeed");

    // The EOF above is produced inside the same poll that then attempts the
    // final transport close. Wait for that poll to finish, so the prover is
    // parked on the still-blocked close before the session is torn down.
    let settled = async {
        while in_poll.load(Ordering::SeqCst) > 0 {
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(TIMEOUT, settled)
        .await
        .expect("prover should settle after blocking the transport close");

    // Close the session while the prover is parked on the blocked transport
    // close. Dropping the drivers marks the session closure and wakes the
    // participants that registered for it.
    p_driver.abort();
    v_driver.abort();
    let _ = p_driver.await;
    let _ = v_driver.await;

    // Let the pending transport close complete.
    gate.open();

    let result = tokio::time::timeout(TIMEOUT, prover_task)
        .await
        .expect("prover should resolve after the transport close completes")
        .expect("prover task should not panic");

    verifier_task.abort();
    server_task.abort();

    result.expect(
        "a session closing after the TLS output must not fail the prover's connection phase",
    );
}
