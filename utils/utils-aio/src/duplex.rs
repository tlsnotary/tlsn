use futures::{channel::mpsc, AsyncRead, AsyncWrite, Sink, Stream};
use std::{
    io::{Error, ErrorKind},
    pin::Pin,
};

pub trait DuplexByteStream: AsyncWrite + AsyncRead + Unpin {}

impl<T> DuplexByteStream for T where T: AsyncWrite + AsyncRead + Unpin {}

#[derive(Debug)]
pub struct DuplexChannel<T> {
    sink: mpsc::Sender<T>,
    stream: mpsc::Receiver<T>,
}

impl<T> DuplexChannel<T>
where
    T: Send + 'static,
{
    pub fn new() -> (Self, Self) {
        let (sender, receiver) = mpsc::channel(10);
        let (sender_2, receiver_2) = mpsc::channel(10);
        (
            Self {
                sink: sender,
                stream: receiver_2,
            },
            Self {
                sink: sender_2,
                stream: receiver,
            },
        )
    }
}

impl<T> Sink<T> for DuplexChannel<T>
where
    T: Send + 'static,
{
    type Error = std::io::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_ready(cx)
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        Pin::new(&mut self.sink)
            .start_send(item)
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_flush(cx)
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_close(cx)
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }
}

impl<T> Stream for DuplexChannel<T> {
    type Item = Result<T, std::io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx).map(|x| x.map(Ok))
    }
}
