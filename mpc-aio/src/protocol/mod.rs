use futures::{Sink, Stream};
use thiserror::Error;

#[cfg(feature = "ot")]
pub mod ot;
//#[cfg(feature = "pa")]
//pub mod point_addition;

pub trait Protocol {
    type Message;
    type Error: std::error::Error;
}

#[derive(Debug, Error)]
pub enum Error<T: std::error::Error> {
    #[error("IOError")]
    IOError,
    #[error("BaseError: {0}")]
    BaseError(#[from] T),
}

pub struct Agent<T>
where
    T: Protocol,
{
    inner: T,
    stream: Box<dyn Stream<Item = <T as Protocol>::Message> + Send>,
    sink: Box<dyn Sink<<T as Protocol>::Message, Error = Error<<T as Protocol>::Error>> + Send>,
}
