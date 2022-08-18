pub mod base;
pub mod extension;

pub use base::*;
pub use extension::*;

pub trait OTSlice {
    fn slice(&mut self, N: usize) -> Self;
}
