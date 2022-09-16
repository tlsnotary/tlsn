pub mod codec;
pub mod duplex;
pub mod muxer;

pub trait Channel<T>: futures::Stream<Item = T> + futures::Sink<T> + Send + Unpin {}
