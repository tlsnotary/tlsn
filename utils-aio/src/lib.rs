pub mod adaptive_barrier;
#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "duplex")]
pub mod duplex;
pub mod expect_msg;
#[cfg(feature = "mux")]
pub mod mux;

pub trait Channel<T>: futures::Stream<Item = T> + futures::Sink<T> + Send + Unpin {}
