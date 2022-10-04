#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "duplex")]
pub mod duplex;
// #[cfg(feature = "muxer")]
// pub mod muxer;
pub mod adaptive_barrier;
pub mod expect_msg;

pub trait Channel<T>: futures::Stream<Item = T> + futures::Sink<T> + Send + Unpin {}
