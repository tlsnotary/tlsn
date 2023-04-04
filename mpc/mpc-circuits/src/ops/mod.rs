//! Operations on binary encoded types.

pub(crate) mod binary;
mod uint;

/// Addition of two integers using so called "wrapping addition", which
/// allows bit overflow.
pub trait WrappingAdd<Rhs> {
    /// The result type after wrapping addition.
    type Output;

    /// Adds two integers with wrapping addition.
    ///
    /// # Example
    ///
    /// ```
    /// assert_eq!(255u8.wrapping_add(2u8), 1u8);
    /// ```
    fn wrapping_add(self, rhs: Rhs) -> Self::Output;
}

/// Subtraction of two integers using so called "wrapping subtraction", which
/// allows bit underflow.
pub trait WrappingSub<Rhs> {
    /// The result type after wrapping subtraction.
    type Output;

    /// Subtracts two integers with wrapping subtraction.
    ///
    /// # Example
    ///
    /// ```
    /// assert_eq!(0u8.wrapping_sub(2u8), 254u8);
    /// ```
    fn wrapping_sub(self, rhs: Rhs) -> Self::Output;
}
