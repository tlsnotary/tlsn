//! Multiplexer used in the TLSNotary protocol.

use std::future::IntoFuture;

use futures::{
    future::{FusedFuture, FutureExt},
    AsyncRead, AsyncWrite, Future,
};
use serio::codec::Bincode;
use tracing::error;
use uid_mux::{yamux, FramedMux};

use crate::Role;

/// Multiplexer supporting unique deterministic stream IDs.
pub type Mux<Io> = yamux::Yamux<Io>;
/// Multiplexer controller providing streams with a codec attached.
pub type MuxControl = FramedMux<yamux::YamuxCtrl, Bincode>;

/// Multiplexer future which must be polled for the muxer to make progress.
pub struct MuxFuture(
    Box<dyn FusedFuture<Output = Result<(), yamux::ConnectionError>> + Send + Unpin>,
);

impl MuxFuture {
    /// Returns true if the muxer is complete.
    pub fn is_complete(&self) -> bool {
        self.0.is_terminated()
    }

    /// Awaits a future, polling the muxer future concurrently.
    pub async fn poll_with<F, R>(&mut self, fut: F) -> R
    where
        F: Future<Output = R>,
    {
        let mut fut = Box::pin(fut.fuse());
        // Poll the future concurrently with the muxer future.
        // If the muxer returns an error, continue polling the future
        // until it completes.
        loop {
            futures::select! {
                res = fut => return res,
                res = &mut self.0 => if let Err(e) = res {
                    error!("mux error: {:?}", e);
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
        self.0.as_mut().poll_unpin(cx)
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
pub fn attach_mux<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    role: Role,
) -> (MuxFuture, MuxControl) {
    let mut mux_config = yamux::Config::default();
    mux_config.set_max_num_streams(64);

    let mux_role = match role {
        Role::Prover => yamux::Mode::Client,
        Role::Verifier => yamux::Mode::Server,
    };

    let mux = Mux::new(socket, mux_config, mux_role);
    let ctrl = FramedMux::new(mux.control(), Bincode);

    if let Role::Prover = role {
        ctrl.mux().alloc(64);
    }

    (MuxFuture(Box::new(mux.into_future().fuse())), ctrl)
}
