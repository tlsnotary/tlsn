#[cfg(feature = "ot")]
pub mod ot;
//#[cfg(feature = "pa")]
//pub mod point_addition;
pub mod garble;

pub trait Protocol {
    type Message: Send + 'static;
    #[cfg(not(test))]
    type Error: std::error::Error;
    #[cfg(test)]
    type Error: std::error::Error + From<tokio_util::sync::PollSendError<Self::Message>>;
}

pub trait Channel<T>: futures::Stream<Item = T> + futures::Sink<T> + Send {}

#[cfg(test)]
mod duplex {
    use super::Channel;
    use futures::{Sink, Stream};
    use std::{
        io::{Error, ErrorKind},
        pin::Pin,
    };
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_util::sync::PollSender;

    pub struct DuplexChannel<T> {
        sink: PollSender<T>,
        stream: ReceiverStream<T>,
    }

    impl<T> DuplexChannel<T>
    where
        T: Send,
    {
        pub fn new() -> (Self, Self) {
            let (sender, receiver) = mpsc::channel(10);
            let (sender_2, receiver_2) = mpsc::channel(10);
            let (sink, stream) = (PollSender::new(sender), ReceiverStream::new(receiver_2));
            let (sink_2, stream_2) = (PollSender::new(sender_2), ReceiverStream::new(receiver));
            (
                Self { sink, stream },
                Self {
                    sink: sink_2,
                    stream: stream_2,
                },
            )
        }
    }

    impl<T> Sink<T> for DuplexChannel<T>
    where
        T: Send,
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
        type Item = T;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            Pin::new(&mut self.stream).poll_next(cx)
        }
    }

    impl<T> Channel<T> for DuplexChannel<T> where T: Send {}
}
