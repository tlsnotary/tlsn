use bytes::Bytes;
use futures::{
    channel::{
        mpsc::{Receiver, SendError, Sender},
        oneshot,
    },
    sink::SinkMapErr,
    AsyncRead, AsyncWrite, Future, SinkExt,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio_util::{
    compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt},
    io::{CopyToBytes, SinkWriter, StreamReader},
};

type CompatSinkWriter =
    Compat<SinkWriter<CopyToBytes<SinkMapErr<Sender<Bytes>, fn(SendError) -> std::io::Error>>>>;

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
    tx_sender: CompatSinkWriter,
    rx_receiver: Compat<StreamReader<Receiver<Result<Bytes, std::io::Error>>, Bytes>>,
    close_send: Option<oneshot::Sender<oneshot::Sender<()>>>,
    close_wait: Option<oneshot::Receiver<()>>,
}

impl TlsConnection {
    /// Creates a new TLS connection.
    pub(crate) fn new(
        tx_sender: Sender<Bytes>,
        rx_receiver: Receiver<Result<Bytes, std::io::Error>>,
        close_send: oneshot::Sender<oneshot::Sender<()>>,
    ) -> Self {
        fn convert_error(err: SendError) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::Other, err)
        }

        Self {
            tx_sender: SinkWriter::new(CopyToBytes::new(
                tx_sender.sink_map_err(convert_error as fn(SendError) -> std::io::Error),
            ))
            .compat_write(),
            rx_receiver: StreamReader::new(rx_receiver).compat(),
            close_send: Some(close_send),
            close_wait: None,
        }
    }
}

impl Drop for TlsConnection {
    fn drop(&mut self) {
        if let Some(close) = self.close_send.take() {
            let (wait_send, _) = oneshot::channel();
            _ = close.send(wait_send);
        }
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.rx_receiver).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.tx_sender).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.tx_sender).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(wait) = self.close_wait.as_mut() {
            Pin::new(wait).poll(cx).map(|_| Ok(()))
        } else {
            let (wait_send, wait_recv) = oneshot::channel();
            let close_send = self.close_send.take().expect("close_trigger is set");

            self.close_wait = Some(wait_recv);

            _ = close_send.send(wait_send);

            Pin::new(self.close_wait.as_mut().unwrap())
                .poll(cx)
                .map(|_| Ok(()))
        }
    }
}
