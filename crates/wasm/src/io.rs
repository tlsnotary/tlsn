use core::slice;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;

pin_project! {
    #[derive(Debug)]
    pub(crate) struct FuturesIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> FuturesIo<T> {
    /// Create a new `FuturesIo` wrapping the given I/O object.
    ///
    /// # Safety
    ///
    /// This wrapper is only safe to use if the inner I/O object does not under
    /// any circumstance read from the buffer passed to `poll_read` in the
    /// `futures::AsyncRead` implementation.
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> hyper::rt::Write for FuturesIo<T>
where
    T: futures::AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_close(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}

// Adapted from https://github.com/hyperium/hyper-util/blob/99b77a5a6f75f24bc0bcb4ca74b5f26a07b19c80/src/rt/tokio.rs
impl<T> hyper::rt::Read for FuturesIo<T>
where
    T: futures::AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // Safety: buf_slice should only be written to, so it's safe to convert `&mut
        // [MaybeUninit<u8>]` to `&mut [u8]`.
        let buf_slice = unsafe {
            slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
        };

        let n = match futures::AsyncRead::poll_read(self.project().inner, cx, buf_slice) {
            Poll::Ready(Ok(n)) => n,
            other => return other.map_ok(|_| ()),
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}
