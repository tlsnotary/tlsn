#[cfg(feature = "ot")]
pub mod ot;
//#[cfg(feature = "pa")]
//pub mod point_addition;
pub mod garble;

pub trait Protocol {
    type Message: Send + 'static;
    type Error: std::error::Error;
}
