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
/// Other traced functions can be called from within the traced function, using the [`dep`](crate::dep) macro.
///
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
pub use mpc_circuits_macros::trace;

/// An attribute macro that is used in combination with [`trace`](crate::trace) to indicate that a function
/// has a dependency on another traced function.
///
/// This is used to replace the path of a function call with the path of its trace.
///
/// # Path override
///
/// The default path of the trace is the original path appended with the `_trace` suffix.
///
/// This can be overriden by passing the path in as the second argument to the macro.
///
/// # Example
///
///  ```
/// use mpc_circuits::{trace, evaluate, dep, CircuitBuilder};
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
pub use mpc_circuits_macros::dep;

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
