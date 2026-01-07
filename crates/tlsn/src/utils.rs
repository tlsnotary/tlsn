//! Execution context.

use std::{
    io::ErrorKind,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, future::FusedFuture};
use futures_plex::DuplexStream;
use mpz_common::context::Multithread;

use crate::mux::MuxControl;

/// Maximum concurrency for multi-threaded context.
pub(crate) const MAX_CONCURRENCY: usize = 8;

/// Builds a multi-threaded context with the given muxer.
pub(crate) fn build_mt_context(mux: MuxControl) -> Multithread {
    let builder = Multithread::builder().mux(mux).concurrency(MAX_CONCURRENCY);

    #[cfg(all(feature = "web", target_arch = "wasm32"))]
    let builder = builder.spawn_handler(|f| {
        let _ = web_spawn::spawn(f);
        Ok(())
    });

    builder.build().unwrap()
}

/// Polls the future while copying bytes between two duplex streams.
///
/// Returns as soon as the future is ready, without closing IO.
pub(crate) async fn await_with_copy_io<'a, S, T>(
    mut fut: Pin<Box<dyn FusedFuture<Output = T> + Send + 'a>>,
    io: S,
    duplex: &mut DuplexStream,
) -> T
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut copy = CopyIo::new(io, duplex);

    loop {
        futures::select! {
            _ = copy => (),
            output = fut => break output
        }
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub(crate) struct CopyIo<'a, S> {
        #[pin]
        io: S,
        #[pin]
        duplex: &'a mut DuplexStream,
        io_done: bool,
        duplex_done: bool,
    }
}

impl<'a, S> CopyIo<'a, S> {
    pub(crate) fn new(io: S, duplex: &'a mut DuplexStream) -> Self {
        Self {
            io,
            duplex,
            io_done: false,
            duplex_done: false,
        }
    }
}

impl<'a, S> Future for CopyIo<'a, S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    type Output = std::io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            let mut is_pending = true;

            if !*this.duplex_done {
                match this.duplex.poll_read_to(cx, this.io.as_mut()) {
                    Poll::Ready(Ok(read)) if read > 0 => is_pending = false,
                    Poll::Ready(Ok(_)) => {
                        is_pending = false;
                        *this.duplex_done = true;
                    }
                    Poll::Ready(Err(err))
                        if err.kind() == ErrorKind::BrokenPipe
                            || err.kind() == ErrorKind::ConnectionReset
                            || err.kind() == ErrorKind::NotConnected =>
                    {
                        is_pending = false;
                        *this.duplex_done = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => (),
                }
            }

            if !*this.io_done {
                match this.duplex.poll_write_from(cx, this.io.as_mut()) {
                    Poll::Ready(Ok(write)) if write > 0 => is_pending = false,
                    Poll::Ready(Ok(_)) => {
                        is_pending = false;
                        *this.io_done = true;
                    }
                    Poll::Ready(Err(err))
                        if err.kind() == ErrorKind::BrokenPipe
                            || err.kind() == ErrorKind::ConnectionReset
                            || err.kind() == ErrorKind::NotConnected =>
                    {
                        is_pending = false;
                        *this.io_done = true
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => (),
                }
            }

            if *this.io_done || *this.duplex_done {
                return Poll::Ready(Ok(()));
            } else if is_pending {
                return Poll::Pending;
            }
        }
    }
}

impl<'a, S> FusedFuture for CopyIo<'a, S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn is_terminated(&self) -> bool {
        self.duplex_done || self.io_done
    }
}
