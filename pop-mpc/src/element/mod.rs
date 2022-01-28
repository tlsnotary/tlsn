mod boolean;

pub use boolean::Bool;

/// An element that has some modulus
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}
