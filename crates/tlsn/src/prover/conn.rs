use futures::{AsyncRead, AsyncWrite};
use futures_plex::DuplexStream;
use std::{
    io::Error as IoError,
    pin::Pin,
    task::{Context, Poll},
};

/// A TLS connection to a server.
///
/// This type implements `AsyncRead` and `AsyncWrite` and can be used to
/// communicate with a server using TLS.
///
/// # Note
///
/// This connection is closed on a best-effort basis if this is dropped. To
/// ensure a clean close, you should call
/// [`AsyncWriteExt::close`](futures::io::AsyncWriteExt::close) to close the
/// connection.
#[derive(Debug)]
pub struct TlsConnection(DuplexStream);

impl TlsConnection {
    pub(crate) fn new(duplex: DuplexStream) -> Self {
        Self(duplex)
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}
