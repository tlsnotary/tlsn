//! Regression: a client that writes its request and closes its write half
//! while the TLS handshake is still in progress must still have that request
//! delivered.
//!
//! The prover used to abort with "client closed during TLS handshake" as soon
//! as it saw the application close, even though a write-half close is not a
//! disappearance: the client may be gone, but the plaintext it already wrote
//! is still valid and the server still drives the handshake.
//!
//! The server here is held just before its first handshake write, so the
//! application half-close lands mid-handshake deterministically. Once released,
//! the server finishes the handshake and reads the request. The prover must
//! complete and the server must see the whole request. Whether the application
//! is still around to read a response is deliberately not asserted: the point
//! is that already-written data is not discarded.
//!
//! This needs `tlsn_insecure` so the MPC setup is cheap. Run it with:
//!
//! ```text
//! RUSTFLAGS="--cfg tlsn_insecure" \
//!     cargo test -p tlsn --test prover_client_half_close --profile tests-integration
//! ```

#![allow(unexpected_cfgs)]
#![cfg(tlsn_insecure)]

use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures_rustls::{
    TlsAcceptor,
    pki_types::{CertificateDer as RustlsCert, PrivateKeyDer},
    rustls::ServerConfig,
};
use tls_server_fixture::{
    APP_RECORD_LENGTH, CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER,
};
use tlsn::{
    Session,
    config::{
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tokio::{
    io::DuplexStream,
    sync::{Notify, oneshot},
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

const TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST: &[u8] = b"GET /request HTTP/1.0\r\n\r\n";
const TRANSPORT_CAP: usize = 2 << 16;

/// Holds the server's first write until the test releases it.
struct Gate {
    open: AtomicBool,
    first_write: Notify,
    wakers: Mutex<Vec<Waker>>,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            open: AtomicBool::new(false),
            first_write: Notify::new(),
            wakers: Mutex::new(Vec::new()),
        })
    }

    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        let wakers: Vec<Waker> = self.wakers.lock().unwrap().drain(..).collect();
        for waker in wakers {
            waker.wake();
        }
    }

    fn register(&self, waker: &Waker) {
        let mut wakers = self.wakers.lock().unwrap();
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }
}

/// A socket whose writes are held back until the gate opens.
struct GatedWrite<S> {
    inner: S,
    gate: Arc<Gate>,
}

impl<S> AsyncRead for GatedWrite<S>
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

impl<S> AsyncWrite for GatedWrite<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.gate.open.load(Ordering::SeqCst) {
            self.gate.first_write.notify_one();
            self.gate.register(cx.waker());
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.gate.open.load(Ordering::SeqCst) {
            self.gate.first_write.notify_one();
            self.gate.register(cx.waker());
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Completes the handshake once the gate opens, reads one request record,
/// reports it and sends `close_notify`. The socket is kept open afterwards so
/// the prover can finish sending its side while the transport still exists.
async fn gated_server(
    peer: Compat<DuplexStream>,
    gate: Arc<Gate>,
    request_tx: oneshot::Sender<Vec<u8>>,
    send_response: bool,
) -> Result<(), String> {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = RustlsCert::from(SERVER_CERT_DER);
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|err| err.to_string())?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let mut conn = acceptor
        .accept(GatedWrite { inner: peer, gate })
        .await
        .map_err(|err| format!("server handshake failed: {err}"))?;

    let mut request = vec![0u8; APP_RECORD_LENGTH];
    conn.read_exact(&mut request)
        .await
        .map_err(|err| format!("server read failed: {err}"))?;
    let _ = request_tx.send(request);

    if send_response {
        conn.write_all(b"hello")
            .await
            .map_err(|err| format!("server response write failed: {err}"))?;
        conn.flush()
            .await
            .map_err(|err| format!("server response flush failed: {err}"))?;
    }

    conn.get_mut().1.send_close_notify();
    conn.flush()
        .await
        .map_err(|err| format!("server close_notify flush failed: {err}"))?;

    // The client half-closed its write side, so the server must observe a
    // clean close_notify rather than an abrupt reset.
    let n = tokio::time::timeout(TIMEOUT, conn.read(&mut [0u8; 1]))
        .await
        .map_err(|_| "timed out waiting for the client close_notify".to_string())?
        .map_err(|err| format!("client close_notify read failed: {err}"))?;
    if n != 0 {
        return Err(format!(
            "expected a clean client close_notify, got {n} bytes"
        ));
    }

    std::future::pending::<()>().await;
    Ok(())
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

fn pad_record(request: &[u8]) -> Vec<u8> {
    let mut record = request.to_vec();
    record.resize(APP_RECORD_LENGTH, 0);
    record
}

#[derive(Clone, Copy)]
enum Mode {
    Mpc,
    Proxy,
}

async fn run(mode: Mode, response: Option<&'static [u8]>) {
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
    let p_driver = tokio::spawn(p_driver);
    let v_driver = tokio::spawn(v_driver);

    let gate = Gate::new();
    let (request_tx, request_rx) = oneshot::channel();

    let (mut conn, prover_task, verifier_task, server_task) = match mode {
        Mode::Mpc => {
            let (prover, verifier) = tokio::join!(prover.commit(mpc_config()), async {
                let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
                    panic!("expected MPC commit protocol");
                };
                verifier.accept().await.unwrap()
            });
            let prover = prover.unwrap();

            let verifier_task = tokio::spawn(async move {
                let _ = verifier.run().await;
            });

            let (client_io, server_peer) = tokio::io::duplex(TRANSPORT_CAP);
            let server_task = tokio::spawn(gated_server(
                server_peer.compat(),
                gate.clone(),
                request_tx,
                response.is_some(),
            ));

            let (conn, prover) = prover
                .connect(tls_client_config(), client_io.compat())
                .unwrap();
            let prover_task = tokio::spawn(async move {
                prover
                    .into_future()
                    .await
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            });

            (conn, prover_task, verifier_task, server_task)
        }
        Mode::Proxy => {
            let (prover, verifier) = tokio::join!(prover.commit(proxy_config()), async {
                let VerifierCommitStart::Proxy(verifier) = verifier.commit().await.unwrap() else {
                    panic!("expected proxy commit protocol");
                };
                verifier.accept().await.unwrap()
            });
            let prover = prover.unwrap();

            let (server_io, server_peer) = tokio::io::duplex(TRANSPORT_CAP);
            let verifier_task = tokio::spawn(async move {
                let _ = verifier.run(server_io.compat()).await;
            });
            let server_task = tokio::spawn(gated_server(
                server_peer.compat(),
                gate.clone(),
                request_tx,
                response.is_some(),
            ));

            let (conn, prover) = prover.connect(tls_client_config()).unwrap();
            let prover_task = tokio::spawn(async move {
                prover
                    .into_future()
                    .await
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            });

            (conn, prover_task, verifier_task, server_task)
        }
    };

    // The server has read the ClientHello and is blocked before its first
    // handshake write. The handshake is therefore still in progress.
    tokio::time::timeout(TIMEOUT, gate.first_write.notified())
        .await
        .expect("server should start the handshake");

    let request = pad_record(REQUEST);
    conn.write_all(&request).await.unwrap();
    // Half-close the application's write side while the handshake is gated.
    conn.close().await.unwrap();

    // Let the prover take the request before the server's handshake data
    // arrives, so the EOF is observed while the handshake is still running.
    tokio::time::sleep(Duration::from_millis(50)).await;
    gate.open();

    if let Some(expected) = response {
        // The application closed only its write half, so it must still receive
        // the server's response and then EOF.
        let mut received_response = Vec::new();
        tokio::time::timeout(TIMEOUT, conn.read_to_end(&mut received_response))
            .await
            .expect("app must receive the response and EOF")
            .expect("response read should not fail");
        assert_eq!(received_response, expected, "app must receive the response");
    }

    let prover_out = tokio::time::timeout(TIMEOUT, prover_task)
        .await
        .expect("prover must not hang after a client write-half close")
        .expect("prover task must not panic");
    assert!(
        prover_out.is_ok(),
        "prover failed after the client half-closed: {:?}",
        prover_out.err()
    );

    // The server must receive the request even though the application closed
    // its write half before the handshake completed.
    let received = tokio::time::timeout(TIMEOUT, request_rx)
        .await
        .expect("server must read the request")
        .expect("server should report the request");
    assert_eq!(received, request, "server must receive the whole request");

    server_task.abort();
    verifier_task.abort();
    p_driver.abort();
    v_driver.abort();
    let _ = (p_handle, v_handle);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_half_close_mid_handshake_mpc() {
    run(Mode::Mpc, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_half_close_mid_handshake_proxy() {
    run(Mode::Proxy, None).await;
}

/// A proxy client that half-closes before the response arrives must still
/// receive the server's plaintext before EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_half_close_mid_handshake_receives_response() {
    run(Mode::Proxy, Some(b"hello")).await;
}
