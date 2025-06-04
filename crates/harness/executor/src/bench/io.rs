use std::{
    io::Result,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;

pin_project! {
    pub(crate) struct Meter<Io> {
        sent: Arc<AtomicU64>,
        recv: Arc<AtomicU64>,
        #[pin] io: Io,
    }
}

impl<Io> Meter<Io> {
    pub(crate) fn new(io: Io) -> Self {
        Self {
            sent: Arc::new(AtomicU64::new(0)),
            recv: Arc::new(AtomicU64::new(0)),
            io,
        }
    }

    pub(crate) fn sent(&self) -> Arc<AtomicU64> {
        self.sent.clone()
    }

    pub(crate) fn recv(&self) -> Arc<AtomicU64> {
        self.recv.clone()
    }
}

impl<Io> AsyncWrite for Meter<Io>
where
    Io: AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let this = self.project();
        this.io.poll_write(cx, buf).map(|res| {
            res.inspect(|n| {
                this.sent.fetch_add(*n as u64, Ordering::Relaxed);
            })
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.project().io.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.project().io.poll_close(cx)
    }
}

impl<Io> AsyncRead for Meter<Io>
where
    Io: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        let this = self.project();
        this.io.poll_read(cx, buf).map(|res| {
            res.inspect(|n| {
                this.recv.fetch_add(*n as u64, Ordering::Relaxed);
            })
        })
    }
}
