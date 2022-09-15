#[cfg(feature = "ot")]
pub mod ot;
//#[cfg(feature = "pa")]
//pub mod point_addition;

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
    use super::{Channel, Protocol};
    use futures::{Sink, Stream};
    use std::pin::Pin;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_util::sync::PollSender;

    pub struct DuplexChannel<T: Protocol> {
        sink: PollSender<T::Message>,
        stream: ReceiverStream<T::Message>,
    }

    impl<T: Protocol> DuplexChannel<T> {
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

    impl<T: Protocol> Sink<T::Message> for DuplexChannel<T> {
        type Error = T::Error;

        fn poll_ready(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.sink)
                .poll_ready(cx)
                .map_err(Self::Error::from)
        }

        fn start_send(
            mut self: std::pin::Pin<&mut Self>,
            item: T::Message,
        ) -> Result<(), Self::Error> {
            Pin::new(&mut self.sink)
                .start_send(item)
                .map_err(Self::Error::from)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.sink)
                .poll_flush(cx)
                .map_err(Self::Error::from)
        }

        fn poll_close(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.sink)
                .poll_close(cx)
                .map_err(Self::Error::from)
        }
    }

    impl<T: Protocol> Stream for DuplexChannel<T> {
        type Item = T::Message;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            Pin::new(&mut self.stream).poll_next(cx)
        }
    }

    impl<T: Protocol> Channel<T::Message> for DuplexChannel<T> {}
}
