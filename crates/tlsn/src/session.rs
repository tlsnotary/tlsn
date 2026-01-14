use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use futures::{AsyncRead, AsyncWrite};
use mpz_common::{ThreadId, context::Multithread, io::Io, mux::Mux};
use tlsn_core::config::{prover::ProverConfig, verifier::VerifierConfig};
use tlsn_mux::{Connection, Handle};

use crate::{
    Error, Result,
    prover::{Prover, state as prover_state},
    verifier::{Verifier, state as verifier_state},
};

/// Maximum concurrency for multi-threaded context.
const MAX_CONCURRENCY: usize = 8;

/// Session state.
#[must_use = "session must be polled continuously to make progress, including during closing."]
pub struct Session<Io> {
    conn: Option<Connection<Io>>,
    mt: Multithread,
}

impl<Io> Session<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new session.
    pub fn new(io: Io) -> Self {
        let mut mux_config = tlsn_mux::Config::default();

        mux_config.set_max_num_streams(36);
        mux_config.set_keep_alive(true);
        mux_config.set_close_sync(true);

        let conn = tlsn_mux::Connection::new(io, mux_config);
        let handle = conn.handle().expect("handle should be available");
        let mt = build_mt_context(MuxHandle { handle });

        Self {
            conn: Some(conn),
            mt,
        }
    }

    /// Creates a new prover.
    pub fn new_prover(
        &mut self,
        config: ProverConfig,
    ) -> Result<Prover<prover_state::Initialized>> {
        let ctx = self.mt.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new prover")
                .with_source(e)
        })?;

        Ok(Prover::new(ctx, config))
    }

    /// Creates a new verifier.
    pub fn new_verifier(
        &mut self,
        config: VerifierConfig,
    ) -> Result<Verifier<verifier_state::Initialized>> {
        let ctx = self.mt.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new verifier")
                .with_source(e)
        })?;

        Ok(Verifier::new(ctx, config))
    }

    /// Returns `true` if the session is closed.
    pub fn is_closed(&self) -> bool {
        self.conn
            .as_ref()
            .map(|mux| mux.is_complete())
            .unwrap_or_default()
    }

    /// Closes the session.
    ///
    /// This will cause the session to begin closing. Session must continue to
    /// be polled until completion.
    pub fn close(&mut self) {
        if let Some(conn) = self.conn.as_mut() {
            conn.close()
        }
    }

    /// Attempts to take the IO, returning an error if it is not available.
    pub fn try_take(&mut self) -> Result<Io> {
        let conn = self.conn.take().ok_or_else(|| {
            Error::io().with_msg("failed to take the session io, it was already taken")
        })?;

        match conn.try_into_io() {
            Err(conn) => {
                self.conn = Some(conn);
                Err(Error::io()
                    .with_msg("failed to take the session io, session was not completed yet"))
            }
            Ok(conn) => Ok(conn),
        }
    }

    /// Polls the session.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.conn
            .as_mut()
            .ok_or_else(|| {
                Error::io()
                    .with_msg("failed to poll the session connection because it has been taken")
            })?
            .poll(cx)
            .map_err(|e| {
                Error::io()
                    .with_msg("error occurred while polling the session connection")
                    .with_source(e)
            })
    }

    /// Splits the session into a driver and handle.
    ///
    /// The driver must be polled to make progress. The handle is used
    /// for creating provers/verifiers and closing the session.
    pub fn split(self) -> (SessionDriver<Io>, SessionHandle) {
        let should_close = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None::<Waker>));

        (
            SessionDriver {
                conn: self.conn,
                should_close: should_close.clone(),
                waker: waker.clone(),
            },
            SessionHandle {
                mt: self.mt,
                should_close,
                waker,
            },
        )
    }
}

impl<Io> Future for Session<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Session::poll(&mut (*self), cx)
    }
}

/// The polling half of a split session.
///
/// Must be polled continuously to drive the session. Returns the underlying
/// IO when the session closes.
#[must_use = "driver must be polled to make progress"]
pub struct SessionDriver<Io> {
    conn: Option<Connection<Io>>,
    should_close: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl<Io> SessionDriver<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    /// Polls the driver.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Io>> {
        // Store the waker so the handle can wake us when close() is called.
        {
            let mut waker_guard = self.waker.lock().unwrap();
            *waker_guard = Some(cx.waker().clone());
        }

        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| Error::io().with_msg("session driver already completed"))?;

        if self.should_close.load(Ordering::Acquire) {
            conn.close();
        }

        match conn.poll(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(Error::io()
                    .with_msg("error polling session connection")
                    .with_source(e)));
            }
            Poll::Pending => return Poll::Pending,
        }

        let conn = self.conn.take().unwrap();
        Poll::Ready(
            conn.try_into_io()
                .map_err(|_| Error::io().with_msg("failed to take session io")),
        )
    }
}

impl<Io> Future for SessionDriver<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<Io>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        SessionDriver::poll(&mut *self, cx)
    }
}

/// The control half of a split session.
///
/// Used to create provers/verifiers and control the session lifecycle.
pub struct SessionHandle {
    mt: Multithread,
    should_close: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl SessionHandle {
    /// Creates a new prover.
    pub fn new_prover(
        &mut self,
        config: ProverConfig,
    ) -> Result<Prover<prover_state::Initialized>> {
        let ctx = self.mt.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new prover")
                .with_source(e)
        })?;

        Ok(Prover::new(ctx, config))
    }

    /// Creates a new verifier.
    pub fn new_verifier(
        &mut self,
        config: VerifierConfig,
    ) -> Result<Verifier<verifier_state::Initialized>> {
        let ctx = self.mt.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new verifier")
                .with_source(e)
        })?;

        Ok(Verifier::new(ctx, config))
    }

    /// Signals the session to close.
    ///
    /// The driver must continue to be polled until it completes.
    pub fn close(&self) {
        self.should_close.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// Multiplexer controller providing streams.
struct MuxHandle {
    handle: Handle,
}

impl std::fmt::Debug for MuxHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxHandle").finish_non_exhaustive()
    }
}

impl Mux for MuxHandle {
    fn open(&self, id: ThreadId) -> Result<Io, std::io::Error> {
        let stream = self
            .handle
            .new_stream(id.as_ref())
            .map_err(std::io::Error::other)?;
        let io = Io::from_io(stream);

        Ok(io)
    }
}

/// Builds a multi-threaded context with the given muxer.
fn build_mt_context(mux: MuxHandle) -> Multithread {
    let builder = Multithread::builder()
        .mux(Box::new(mux) as Box<_>)
        .concurrency(MAX_CONCURRENCY);

    #[cfg(all(feature = "web", target_arch = "wasm32"))]
    let builder = builder.spawn_handler(|f| {
        let _ = web_spawn::spawn(f);
        Ok(())
    });

    builder.build().unwrap()
}
