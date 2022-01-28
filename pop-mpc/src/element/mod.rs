mod boolean;
mod gate_ops;

pub use boolean::Bool;
pub use gate_ops::GateOps;

/// An element that has some modulus
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}
