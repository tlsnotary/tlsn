//! IO abstraction for the SDK.
//!
//! This module defines the [`Io`] trait which abstracts bidirectional
//! byte streams across different platforms (WASM, iOS, Android, native).

use core::slice;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;

/// A bidirectional byte stream for communication.
///
/// This trait is automatically implemented for any type that implements
/// `AsyncRead + AsyncWrite + Send + Unpin + 'static`.
///
/// Platform-specific adapters implement this trait:
/// - WASM: `JsIoAdapter` wrapping a JavaScript object
/// - iOS/Android: `ForeignIoAdapter` wrapping FFI callbacks
/// - Native: Any tokio or futures-based stream
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Blanket implementation for any compatible type.
impl<T> Io for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

pin_project! {
    /// Adapter that bridges `futures::AsyncRead/AsyncWrite` to `hyper::rt::Read/Write`.
    ///
    /// This is useful for using the SDK's IO streams with hyper's HTTP client.
    #[derive(Debug)]
    pub struct HyperIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> HyperIo<T> {
    /// Creates a new `HyperIo` wrapping the given IO stream.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Returns the inner IO stream.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> hyper::rt::Write for HyperIo<T>
where
    T: AsyncWrite + Unpin,
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

impl<T> hyper::rt::Read for HyperIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // The cast from MaybeUninit<u8> to u8 is sound because AsyncRead
        // implementations only write to the buffer, never read from it.
        let buf_slice = unsafe {
            slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
        };

        let n = match AsyncRead::poll_read(self.project().inner, cx, buf_slice) {
            Poll::Ready(Ok(n)) => n,
            other => return other.map_ok(|_| ()),
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify that common types implement Io.
    fn _assert_io<T: Io>() {}
}
