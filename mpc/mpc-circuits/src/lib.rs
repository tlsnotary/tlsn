//! This crate provides types for representing computation as binary circuits.
#![deny(missing_docs, unreachable_pub, unused_must_use)]

extern crate self as mpc_circuits;

mod builder;
mod circuit;
pub mod circuits;
pub(crate) mod components;
pub mod ops;
#[cfg(feature = "parse")]
mod parse;
mod tracer;
pub mod types;

#[doc(hidden)]
pub use builder::BuilderState;
pub use builder::{BuilderError, CircuitBuilder};
pub use circuit::{Circuit, CircuitError};
#[doc(hidden)]
pub use components::{Feed, Node, Sink};
pub use components::{Gate, GateType};
pub use tracer::Tracer;

pub use once_cell;

/// An attribute macro that can be applied to a function to automatically convert
/// it into a circuit.
///
/// # Example
///
/// ```
/// use mpc_circuits::{trace, evaluate, CircuitBuilder};
///
/// #[trace]
/// fn bitxor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
///     std::array::from_fn(|i| a[i] ^ b[i])
/// }
///
/// fn main() {
///     let builder = CircuitBuilder::new();
///     let a = builder.add_array_input::<u8, 16>();
///     let b = builder.add_array_input::<u8, 16>();
///
///     let c = bitxor_trace(&mut builder.state(), a, b);
///
///     builder.add_output(c);
///
///     let circ = builder.build().unwrap();
///
///     let a = [42u8; 16];
///     let b = [69u8; 16];
///
///     let output = evaluate!(circ, fn(a, b) -> [u8; 16]).unwrap();
///
///     assert_eq!(output, bitxor(a, b));
/// }
/// ```
///
/// # Dependencies
///
/// Dependencies can be specified using the `#[dep]` attribute. This will replace any calls
/// to the specified function with the provided trace function.
///
/// ## Path override
///
/// The default path of the trace is the original path appended with the `_trace` suffix.
///
/// This can be overriden by passing the path in as the second argument to the attribute, eg `#[dep(old_path, new_path)]`.
///
/// ## Example
///
///  ```
/// use mpc_circuits::{trace, evaluate, CircuitBuilder};
///
/// #[trace]
/// fn bitxor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
///     std::array::from_fn(|i| a[i] ^ b[i])
/// }
///
/// #[trace]
/// fn bitand(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
///     std::array::from_fn(|i| a[i] & b[i])
/// }
///
/// #[trace]
/// #[dep(bitxor, bitxor_trace)]
/// #[dep(bitand)]
/// fn bitxor_and(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
///     bitxor(a, bitand(a, b))
/// }
///
/// fn main() {
///    let builder = CircuitBuilder::new();
///    let a = builder.add_array_input::<u8, 16>();
///    let b = builder.add_array_input::<u8, 16>();
///
///    let c = bitxor_and_trace(&mut builder.state(), a, b);
///
///    builder.add_output(c);
///
///    let circ = builder.build().unwrap();
///
///    let a = [42u8; 16];
///    let b = [69u8; 16];
///
///    let output = evaluate!(circ, fn(a, b) -> [u8; 16]).unwrap();
///
///    assert_eq!(output, bitxor_and(a, b));
/// }
/// ```
/// # Cache
///
/// The macro can optionally be configured with the `cache` argument which will cache the circuit
/// after the first invocation. This can be useful for functions that will be used multiple times.
///
/// The circuit will be cached for the lifetime of the program.
///
/// # Suffix
///
/// The macro copies the traced function and appends the `_trace` suffix to the end of the name.
///
/// This preserves the original function, which can be used for testing.
///
/// This suffix can be overriden by passing the `suffix = "new_suffix"` argument to the macro.
pub use mpc_circuits_macros::trace;

/// Evaluates a circuit and attempts to coerce the output into the specified return type
/// indicated in the function signature.
///
/// # Returns
///
/// The macro returns a `Result` with the output of the circuit or a [`TypeError`](crate::types::TypeError) if the
/// output could not be coerced into the specified return type.
///
/// `Result<T, TypeError>`
///
/// # Example
///
/// ```
/// # let circ = {
/// #    use mpc_circuits::{CircuitBuilder, ops::WrappingAdd};
/// #
/// #    let builder = CircuitBuilder::new();
/// #    let a = builder.add_input::<u8>();
/// #    let b = builder.add_input::<u8>();
/// #    let c = a.wrapping_add(b);
/// #    builder.add_output(c);
/// #    builder.build().unwrap()
/// # };
/// use mpc_circuits::evaluate;
///
/// let output: u8 = evaluate!(circ, fn(1u8, 2u8) -> u8).unwrap();
///
/// assert_eq!(output, 1u8 + 2u8);
/// ```
pub use mpc_circuits_macros::evaluate;

/// Helper macro for testing that a circuit evaluates to the expected value.
///
/// # Example
///
/// ```
/// # let circ = {
/// #    use mpc_circuits::{CircuitBuilder, ops::WrappingAdd};
/// #
/// #    let builder = CircuitBuilder::new();
/// #    let a = builder.add_input::<u8>();
/// #    let b = builder.add_input::<u8>();
/// #    let c = a.wrapping_add(b);
/// #    builder.add_output(c);
/// #    builder.build().unwrap()
/// # };
/// use mpc_circuits::test_circ;
///
/// fn wrapping_add(a: u8, b: u8) -> u8 {
///    a.wrapping_add(b)
/// }
///
/// test_circ!(circ, wrapping_add, fn(1u8, 2u8) -> u8);
/// ```
pub use mpc_circuits_macros::test_circ;
