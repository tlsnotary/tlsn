pub mod adaptive_barrier;
#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "duplex")]
pub mod duplex;
pub mod executor;
pub mod expect_msg;
pub mod factory;
#[cfg(feature = "mux")]
pub mod mux;
pub mod non_blocking_backend;

pub trait Channel<T>:
    futures::Stream<Item = Result<T, std::io::Error>>
    + futures::Sink<T, Error = std::io::Error>
    + Send
    + Sync
    + Unpin
{
}

impl<T, U> Channel<T> for U where
    U: futures::Stream<Item = Result<T, std::io::Error>>
        + futures::Sink<T, Error = std::io::Error>
        + Send
        + Sync
        + Unpin
{
}
