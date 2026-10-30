use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use futures::{
    AsyncReadExt, AsyncWriteExt,
    io::AsyncWrite,
    task::{ArcWake, waker},
};
use tlsn_core::connection::ServerName;

use crate::{
    Error, Result,
    prover::{BUF_CAP, Prover, ProverControl, client::TlsClient, state},
};

/// Counts wake-ups without scheduling any work.
pub(super) struct WakeCounter(AtomicUsize);

impl WakeCounter {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(AtomicUsize::new(0)))
    }

    /// Returns and resets the number of wake-ups observed.
    pub(super) fn take(&self) -> usize {
        self.0.swap(0, Ordering::Relaxed)
    }
}

impl ArcWake for WakeCounter {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Accepts at most `max_write` bytes per poll.
pub(super) struct PartialWriter {
    pub(super) max_write: usize,
    pub(super) written: usize,
}

impl AsyncWrite for PartialWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.max_write.min(buf.len());
        self.written += written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A pinned `Connected` prover with in-memory I/O and a counting waker.
///
/// Keeps the app/server peers alive so tests can feed data in both directions.
pub(super) struct TestProver {
    state: Pin<Box<state::Connected<futures_plex::DuplexStream>>>,
    app_io: Option<futures_plex::DuplexStream>,
    server_peer: futures_plex::DuplexStream,
    wake_counter: Arc<WakeCounter>,
    waker: Waker,
}

impl TestProver {
    pub(super) fn new(tls_client: Box<dyn TlsClient<Error = Error> + Send>) -> Self {
        Self::new_with_client_io_cap(tls_client, BUF_CAP)
    }

    pub(super) fn new_with_client_io_cap(
        tls_client: Box<dyn TlsClient<Error = Error> + Send>,
        client_io_cap: usize,
    ) -> Self {
        let decrypt = tls_client.decrypt();

        let (client_io, app_io) = futures_plex::duplex(client_io_cap);
        let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);
        let (server_socket, server_peer) = futures_plex::duplex(BUF_CAP);

        let state = state::Connected {
            server_name: ServerName::Dns("example.com".try_into().unwrap()),
            tls_client,
            control: ProverControl { decrypt },
            client_io,
            output: None,
            server_socket,
            client_to_server,
            server_to_client,
            client_closed: false,
            server_closed: false,
        };

        let wake_counter = WakeCounter::new();
        let waker = waker(wake_counter.clone());

        Self {
            state: Box::pin(state),
            app_io: Some(app_io),
            server_peer,
            wake_counter,
            waker,
        }
    }

    /// Writes application plaintext into the prover's client I/O.
    pub(super) fn write_plaintext(&mut self, data: &[u8]) {
        let io = self.app_io.as_mut().expect("client is not abandoned");
        futures::executor::block_on(AsyncWriteExt::write_all(io, data)).unwrap();
    }

    /// Reads decrypted plaintext from the application side.
    pub(super) fn read_app(&mut self, buf: &mut [u8]) -> usize {
        let io = self.app_io.as_mut().expect("client is not abandoned");
        futures::executor::block_on(AsyncReadExt::read(io, buf)).unwrap()
    }

    /// Writes server TLS bytes into the prover's server socket.
    pub(super) fn write_server_tls(&mut self, data: &[u8]) {
        futures::executor::block_on(AsyncWriteExt::write_all(&mut self.server_peer, data)).unwrap();
    }

    /// Drops the application end of `client_io`.
    pub(super) fn abandon_client(&mut self) {
        drop(self.app_io.take());
    }

    pub(super) fn poll_io_to(&mut self) -> Result<()> {
        let mut cx = Context::from_waker(&self.waker);
        let mut proj = self.state.as_mut().project();
        Prover::<state::Connected<futures_plex::DuplexStream>>::io_to_tls_client(&mut proj, &mut cx)
    }

    pub(super) fn poll_io_from(&mut self) -> Result<()> {
        let mut cx = Context::from_waker(&self.waker);
        let mut proj = self.state.as_mut().project();
        Prover::<state::Connected<futures_plex::DuplexStream>>::io_from_tls_client(
            &mut proj, &mut cx,
        )
    }

    pub(super) fn poll_io(&mut self) -> Result<()> {
        let mut cx = Context::from_waker(&self.waker);
        let mut proj = self.state.as_mut().project();
        Prover::<state::Connected<futures_plex::DuplexStream>>::poll_io(&mut proj, &mut cx)
    }

    /// Returns and resets the number of wake-ups observed.
    pub(super) fn take_wakes(&self) -> usize {
        self.wake_counter.take()
    }
}
