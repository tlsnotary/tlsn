//! Multiplexer used in the TLSNotary protocol.

use std::{error::Error, future::IntoFuture, mem};

use futures::{
    AsyncRead, AsyncWrite, Future, TryFutureExt,
    future::{FusedFuture, FutureExt, ready},
};
use tracing::error;
use uid_mux::yamux;

use crate::Role;

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Multiplexer supporting unique deterministic stream IDs.
pub(crate) type Mux<Io> = yamux::Yamux<Io>;
/// Multiplexer controller providing streams.
pub(crate) type MuxControl = yamux::YamuxCtrl;

/// Multiplexer future which must be polled for the muxer to make progress.
pub(crate) struct MuxFuture {
    /// The multiplexer future.
    main: Box<dyn FusedFuture<Output = Result<(), yamux::ConnectionError>> + Send + Unpin>,
    /// An auxiliary future which gets polled implicitly alongside the futures
    /// polled with [Self::poll_with].
    ///
    /// This future has no effect on the muxer progress.
    aux: Box<dyn FusedFuture<Output = Result<(), BoxError>> + Send + Unpin>,
    /// The error returned by the `aux` future.
    aux_error: Option<BoxError>,
}

impl MuxFuture {
    /// Creates a new multiplexer future.
    pub(crate) fn new(
        fut: Box<dyn FusedFuture<Output = Result<(), yamux::ConnectionError>> + Send + Unpin>,
    ) -> Self {
        Self {
            main: fut,
            aux: Box::new(ready(Ok(())).fuse()),
            aux_error: None,
        }
    }

    /// Returns true if the muxer is complete.
    pub(crate) fn is_complete(&self) -> bool {
        self.main.is_terminated()
    }

    /// Awaits a future, polling the muxer future concurrently.
    pub(crate) async fn poll_with<F, R>(&mut self, fut: F) -> R
    where
        F: Future<Output = R>,
    {
        let mut fut = Box::pin(fut.fuse());
        // Poll the future concurrently with the muxer future.
        // If the muxer returns an error or if the auxiliary future completes,
        // continue polling the future until it completes.
        loop {
            futures::select! {
                res = fut => return res,
                res = &mut self.main => if let Err(e) = res {
                    error!("mux error: {:?}", e);
                },
                res = &mut self.aux => if let Err(e) = res {
                    error!("aux future error: {:?}", e);
                    self.aux_error = Some(e);
                },
            }
        }
    }

    /// Sets an auxiliary future.
    pub(crate) fn aux<F, E>(&mut self, fut: F)
    where
        F: Future<Output = Result<(), E>> + Send + Unpin + 'static,
        E: Error + Send + Sync + 'static,
    {
        self.aux = Box::new(fut.map_err(|e| -> BoxError { Box::new(e) }).fuse());
        self.aux_error = None;
    }

    /// Awaits the auxiliary future, polling the muxer future concurrently.
    pub(crate) async fn await_aux(&mut self) -> Result<(), BoxError> {
        if self.aux.is_terminated() {
            let err = mem::take(&mut self.aux_error);
            return err.map_or(Ok(()), Err);
        }

        // Poll the future concurrently with the muxer future.
        // If the muxer returns an error, continue polling the future
        // until it completes.
        loop {
            futures::select! {
                res = &mut self.main => if let Err(e) = res {
                    error!("mux error: {:?}", e);
                },
                res = &mut self.aux => {
                    match res {
                        Err(e) => {
                            error!("aux future error: {:?}", e);
                            return Err(e);
                        },
                        _ => return Ok(())
                    }
                },
            }
        }
    }
}

impl Future for MuxFuture {
    type Output = Result<(), yamux::ConnectionError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.main.as_mut().poll_unpin(cx)
    }
}

/// Attaches a multiplexer to the provided socket.
///
/// Returns the multiplexer and a controller for creating streams with a codec
/// attached.
///
/// # Arguments
///
/// * `socket` - The socket to attach the multiplexer to.
/// * `role` - The role of the party using the multiplexer.
pub(crate) fn attach_mux<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    role: Role,
) -> (MuxFuture, MuxControl) {
    let mut mux_config = yamux::Config::default();
    mux_config.set_max_num_streams(36);

    let mux_role = match role {
        Role::Prover => yamux::Mode::Client,
        Role::Verifier => yamux::Mode::Server,
    };

    let mux = Mux::new(socket, mux_config, mux_role);
    let ctrl = mux.control();

    if let Role::Prover = role {
        ctrl.alloc(36);
    }

    (MuxFuture::new(Box::new(mux.into_future().fuse())), ctrl)
}
