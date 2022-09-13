use futures::{Sink, Stream};

#[cfg(feature = "ot")]
pub mod ot;
//#[cfg(feature = "pa")]
//pub mod point_addition;

pub trait Protocol {
    type Message;
    type Error: std::error::Error;
}

pub trait Channel<T>: Stream<Item = T> + Sink<T> + Send {}
