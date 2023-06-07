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
    sink_writer: CompatSinkWriter,
    stream_reader: Compat<StreamReader<Receiver<Result<Bytes, std::io::Error>>, Bytes>>,
    close_trigger: Option<oneshot::Sender<oneshot::Sender<()>>>,
    close_wait: Option<oneshot::Receiver<()>>,
}

impl TlsConnection {
    /// Creates a new TLS connection.
    pub(crate) fn new(
        request_sender: Sender<Bytes>,
        response_receiver: Receiver<Result<Bytes, std::io::Error>>,
        close_trigger: oneshot::Sender<oneshot::Sender<()>>,
    ) -> Self {
        fn convert_error(err: SendError) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::Other, err)
        }

        Self {
            sink_writer: SinkWriter::new(CopyToBytes::new(
                request_sender.sink_map_err(convert_error as fn(SendError) -> std::io::Error),
            ))
            .compat_write(),
            stream_reader: StreamReader::new(response_receiver).compat(),
            close_trigger: Some(close_trigger),
            close_wait: None,
        }
    }
}

impl Drop for TlsConnection {
    fn drop(&mut self) {
        if let Some(close) = self.close_trigger.take() {
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
        Pin::new(&mut self.stream_reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.sink_writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.sink_writer).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(wait) = self.close_wait.as_mut() {
            Pin::new(wait).poll(cx).map(|_| Ok(()))
        } else {
            let (wait_send, wait_recv) = oneshot::channel();
            let trigger_send = self.close_trigger.take().expect("close_trigger is set");

            self.close_wait = Some(wait_recv);

            _ = trigger_send.send(wait_send);

            Pin::new(self.close_wait.as_mut().unwrap())
                .poll(cx)
                .map(|_| Ok(()))
        }
    }
}
