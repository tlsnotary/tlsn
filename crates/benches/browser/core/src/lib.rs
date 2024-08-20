//! Contains core types shared by the native and the wasm components.

use std::{
    io::Error,
    pin::Pin,
    task::{Context, Poll},
};

use tlsn_benches_library::AsyncIo;

use serio::{
    codec::{Bincode, Framed},
    Sink, Stream,
};
use tokio_util::codec::LengthDelimitedCodec;

pub mod msg;

/// A sink/stream for serializable types with a framed transport.
pub struct FramedIo {
    inner:
        serio::Framed<tokio_util::codec::Framed<Box<dyn AsyncIo>, LengthDelimitedCodec>, Bincode>,
}

impl FramedIo {
    /// Creates a new `FramedIo` from the given async `io`.
    #[allow(clippy::default_constructed_unit_structs)]
    pub fn new(io: Box<dyn AsyncIo>) -> Self {
        let io = LengthDelimitedCodec::builder().new_framed(io);
        Self {
            inner: Framed::new(io, Bincode::default()),
        }
    }
}

impl Sink for FramedIo {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn start_send<Item: serio::Serialize>(
        mut self: Pin<&mut Self>,
        item: Item,
    ) -> std::result::Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item)
    }
}

impl Stream for FramedIo {
    type Error = Error;

    fn poll_next<Item: serio::Deserialize>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Item, Error>>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}
