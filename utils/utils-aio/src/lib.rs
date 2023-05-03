pub mod adaptive_barrier;
#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "duplex")]
pub mod duplex;
pub mod expect_msg;
pub mod factory;
#[cfg(feature = "mux")]
pub mod mux;
pub mod non_blocking_backend;
pub mod ring_buffer;

pub trait Channel<T>: futures::Stream<Item = T> + futures::Sink<T> + Send + Unpin {}

impl<T, U> Channel<T> for U where U: futures::Stream<Item = T> + futures::Sink<T> + Send + Unpin {}
