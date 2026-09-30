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
use mpz_common::{Session as MpzSession, ThreadPool, ThreadPoolBuildError, io::Io, mux::Mux};
use tlsn_core::config::{prover::ProverConfig, verifier::VerifierConfig};
use tlsn_mux::{Connection, Handle};

use crate::{
    Error, Result,
    prover::{Prover, state as prover_state},
    verifier::{Verifier, state as verifier_state},
};

/// Configuration for a [`Session`].
#[derive(Debug, Clone)]
pub struct SessionConfig {
    mux: tlsn_mux::Config,
}

impl SessionConfig {
    /// Creates a new builder.
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder::default()
    }

    /// Returns the underlying [`tlsn_mux::Config`].
    fn to_mux_config(&self) -> tlsn_mux::Config {
        self.mux.clone()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            mux: session_mux_config(None).expect("default mux config is valid"),
        }
    }
}

/// Builds a [`tlsn_mux::Config`] with the session's fixed settings applied.
///
/// All mux-specific invariants (e.g. the receive window / stream limit
/// coupling) are validated by [`tlsn_mux::ConfigBuilder`].
fn session_mux_config(
    max_num_streams: Option<usize>,
) -> Result<tlsn_mux::Config, tlsn_mux::ConfigError> {
    let mut builder = tlsn_mux::Config::builder()
        .keep_alive(true)
        .close_sync(true);

    if let Some(max_num_streams) = max_num_streams {
        builder = builder.max_num_streams(max_num_streams);
    }

    builder.build()
}

/// Builder for [`SessionConfig`].
#[derive(Debug, Default)]
pub struct SessionConfigBuilder {
    max_num_streams: Option<usize>,
}

impl SessionConfigBuilder {
    /// Sets the maximum number of concurrent streams per session.
    ///
    /// Defaults to the mux default (512) when unset. The limit is bounded by
    /// the session's receive window (1 GiB by default); higher values are
    /// rejected by [`build`](Self::build).
    pub fn max_num_streams(mut self, max_num_streams: usize) -> Self {
        self.max_num_streams = Some(max_num_streams);
        self
    }

    /// Builds the configuration.
    ///
    /// Returns an error if the requested stream limit exceeds what the
    /// session's receive window supports.
    pub fn build(self) -> Result<SessionConfig, SessionConfigError> {
        Ok(SessionConfig {
            mux: session_mux_config(self.max_num_streams)?,
        })
    }
}

/// Error for [`SessionConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SessionConfigError(#[from] tlsn_mux::ConfigError);

/// A TLSNotary session over a communication channel.
///
/// Wraps an async IO stream and provides multiplexing for the protocol. Use
/// [`new_prover`](Self::new_prover) or [`new_verifier`](Self::new_verifier) to
/// create protocol participants.
///
/// The session must be polled continuously (either directly or via
/// [`split`](Self::split)) to drive the underlying connection. After the
/// session closes, the underlying IO can be reclaimed with
/// [`try_take`](Self::try_take).
///
/// **Important**: The order in which provers and verifiers are created must
/// match on both sides. For example, if the prover side calls `new_prover`
/// then `new_verifier`, the verifier side must call `new_verifier` then
/// `new_prover`.
#[must_use = "session must be polled continuously to make progress, including during closing."]
pub struct Session<Io> {
    conn: Option<Connection<Io>>,
    executor: MpzSession,
    handle: Handle,
}

impl<Io> Session<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new session over `io`, the prover ↔ verifier channel.
    ///
    /// On TCP transports, disable Nagle's algorithm; see
    /// [Performance](crate#performance).
    pub fn new(io: Io) -> Self {
        Self::new_with_config(io, SessionConfig::default())
    }

    /// Creates a new session over `io` with the given configuration.
    ///
    /// On TCP transports, disable Nagle's algorithm; see
    /// [Performance](crate#performance).
    pub fn new_with_config(io: Io, config: SessionConfig) -> Self {
        let mux_config = config.to_mux_config();

        let conn = tlsn_mux::Connection::new(io, mux_config);
        let handle = conn.handle().expect("handle should be available");
        let executor = build_executor(MuxHandle {
            handle: handle.clone(),
        });

        Self {
            conn: Some(conn),
            executor,
            handle,
        }
    }

    /// Creates a new prover.
    pub fn new_prover(
        &mut self,
        config: ProverConfig,
    ) -> Result<Prover<prover_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new prover")
                .with_source(e)
        })?;

        Ok(Prover::new(ctx, self.handle.clone(), config))
    }

    /// Creates a new verifier.
    pub fn new_verifier(
        &mut self,
        config: VerifierConfig,
    ) -> Result<Verifier<verifier_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new verifier")
                .with_source(e)
        })?;

        Ok(Verifier::new(ctx, self.handle.clone(), config))
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
                executor: self.executor,
                should_close,
                waker,
                handle: self.handle,
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
    executor: MpzSession,
    should_close: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
    handle: Handle,
}

impl SessionHandle {
    /// Creates a new prover.
    pub fn new_prover(
        &mut self,
        config: ProverConfig,
    ) -> Result<Prover<prover_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new prover")
                .with_source(e)
        })?;

        Ok(Prover::new(ctx, self.handle.clone(), config))
    }

    /// Creates a new verifier.
    pub fn new_verifier(
        &mut self,
        config: VerifierConfig,
    ) -> Result<Verifier<verifier_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new verifier")
                .with_source(e)
        })?;

        Ok(Verifier::new(ctx, self.handle.clone(), config))
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
    fn open(&self, id: &[u8]) -> Result<Io, std::io::Error> {
        let stream = self.handle.new_stream(id).map_err(std::io::Error::other)?;
        let io = Io::from_io(stream);

        Ok(io)
    }
}

/// Builds a session backed by the process-wide global thread pool, with the
/// given muxer.
fn build_executor(mux: MuxHandle) -> MpzSession {
    #[cfg(all(feature = "web", target_arch = "wasm32"))]
    let cores = web_spawn::available_parallelism().map(|n| n.get());

    #[cfg(not(all(feature = "web", target_arch = "wasm32")))]
    let cores = std::thread::available_parallelism().map(|n| n.get());

    let builder = ThreadPool::builder().num_threads(cores.unwrap_or(8));

    #[cfg(all(feature = "web", target_arch = "wasm32"))]
    let builder = builder.spawn(|f| {
        let _ = web_spawn::spawn(f);
        Ok(())
    });

    // Install our configured pool as the process-wide global pool on first
    // use.
    match builder.build_global() {
        Ok(()) | Err(ThreadPoolBuildError::AlreadyInitialized) => {}
        Err(e) => panic!("failed to build global thread pool: {e}"),
    }

    MpzSession::builder()
        .pool(ThreadPool::global())
        .build(mux)
        .expect("session should build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(SessionConfig::builder().build().is_ok());
    }

    #[test]
    fn oversized_max_num_streams_is_rejected() {
        let err = SessionConfig::builder()
            .max_num_streams(usize::MAX)
            .build()
            .unwrap_err();
        assert!(matches!(
            err.0,
            tlsn_mux::ConfigError::ReceiveWindowTooSmall { .. }
        ));
    }
}
