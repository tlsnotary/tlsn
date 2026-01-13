//! Multiplexer used in the TLSNotary protocol.

use futures::{
    AsyncRead, AsyncWrite, Future,
    future::{FusedFuture, FutureExt},
};
use mpz_common::{ThreadId, io::Io, mux::Mux};
use tlsn_mux::{Connection, Handle};
use tracing::error;

/// Multiplexer controller providing streams.
pub(crate) struct MuxControl {
    handle: Handle,
}

impl Mux for MuxControl {
    fn open(&self, id: ThreadId) -> Result<Io, std::io::Error> {
        let stream = self
            .handle
            .new_stream(id.as_ref())
            .map_err(std::io::Error::other)?;
        let io = Io::from_io(stream);

        Ok(io)
    }
}

impl From<MuxControl> for Box<dyn Mux + Send> {
    fn from(val: MuxControl) -> Self {
        Box::new(val)
    }
}

/// Multiplexer future which must be polled for the muxer to make progress.
#[derive(Debug)]
pub(crate) struct MuxFuture<T> {
    conn: Connection<T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> MuxFuture<T> {
    pub(crate) fn new(socket: T) -> Self {
        let mut mux_config = tlsn_mux::Config::default();

        mux_config.set_max_num_streams(36);
        mux_config.set_keep_alive(true);
        mux_config.set_close_sync(true);

        let conn = tlsn_mux::Connection::new(socket, mux_config);

        Self { conn }
    }

    pub(crate) fn handle(&self) -> Result<MuxControl, std::io::Error> {
        let handle = self.conn.handle().map_err(std::io::Error::other)?;

        Ok(MuxControl { handle })
    }

    pub(crate) fn close(&mut self) {
        self.conn.close();
    }

    pub(crate) fn into_io(self) -> Result<T, std::io::Error> {
        self.conn
            .try_into_io()
            .map_err(|_| std::io::Error::other("unable to return IO, connection is not closed"))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> FusedFuture for MuxFuture<T> {
    fn is_terminated(&self) -> bool {
        self.conn.is_complete()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> MuxFuture<T> {
    /// Awaits a future, polling the muxer future concurrently.
    pub(crate) async fn poll_with<F, R>(&mut self, fut: F) -> R
    where
        F: Future<Output = R>,
    {
        let mut fut = Box::pin(fut.fuse());
        let mut mux = self;
        // Poll the future concurrently with the muxer future.
        // If the muxer returns an error, continue polling the future
        // until it completes.
        loop {
            futures::select! {
                res = fut => return res,
                res = mux => if let Err(e) = res {
                    error!("mux error: {:?}", e);
                },
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Future for MuxFuture<T> {
    type Output = Result<(), tlsn_mux::ConnectionError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.conn.poll(cx)
    }
}
