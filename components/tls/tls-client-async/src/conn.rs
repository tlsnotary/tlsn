use bytes::Bytes;
use futures::{
    channel::mpsc::{Receiver, SendError, Sender},
    sink::SinkMapErr,
    AsyncRead, AsyncWrite, SinkExt,
};
use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind},
    pin::Pin,
    task::{Context, Poll},
};
use tokio_util::{
    compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt},
    io::{CopyToBytes, SinkWriter, StreamReader},
};

type CompatSinkWriter =
    Compat<SinkWriter<CopyToBytes<SinkMapErr<Sender<Bytes>, fn(SendError) -> IoError>>>>;

/// A TLS connection to a server.
///
/// This type implements `AsyncRead` and `AsyncWrite` and can be used to communicate
/// with a server using TLS.
///
/// # Note
///
/// This connection is closed on a best-effort basis if this is dropped. To ensure a clean close, you should call
/// [`AsyncWriteExt::close`](futures::io::AsyncWriteExt::close) to close the connection.
#[derive(Debug)]
pub struct TlsConnection {
    /// The data to be transmitted to the server is sent to this sink.
    tx_sender: CompatSinkWriter,
    /// The data to be received from the server is received from this stream.
    rx_receiver: Compat<StreamReader<Receiver<Result<Bytes, IoError>>, Bytes>>,
}

impl TlsConnection {
    /// Creates a new TLS connection.
    pub(crate) fn new(
        tx_sender: Sender<Bytes>,
        rx_receiver: Receiver<Result<Bytes, IoError>>,
    ) -> Self {
        fn convert_error(err: SendError) -> IoError {
            if err.is_disconnected() {
                IoErrorKind::BrokenPipe.into()
            } else {
                IoErrorKind::WouldBlock.into()
            }
        }

        Self {
            tx_sender: SinkWriter::new(CopyToBytes::new(
                tx_sender.sink_map_err(convert_error as fn(SendError) -> IoError),
            ))
            .compat_write(),
            rx_receiver: StreamReader::new(rx_receiver).compat(),
        }
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.rx_receiver).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.tx_sender).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.tx_sender).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.tx_sender).poll_close(cx)
    }
}
