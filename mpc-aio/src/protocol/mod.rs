#[cfg(feature = "ot")]
pub mod ot;
#[cfg(feature = "pa")]
pub mod point_addition;

pub trait Protocol {
    type Message;
    type Error;
}

pub struct Agent<T>
where
    T: Protocol,
{
    inner: T,
    stream: Box<dyn Stream<Item = <T as Protocol>::Message> + Send>,
    sink: Box<dyn Sink<<T as Protocol>::Message, Error = T::Error> + Send>,
}
