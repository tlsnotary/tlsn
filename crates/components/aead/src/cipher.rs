//! Ciphers and circuits.

use mpz_circuits::{circuits::aes128_trace, once_cell::sync::Lazy, Circuit, CircuitBuilder};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Repr,
};
use std::sync::Arc;

/// A cipher circuit.
pub trait Cipher: Default {
    /// The key type.
    type Key: Repr<Binary>;
    /// The initialization vector type.
    type Iv: Repr<Binary>;
    /// The block type.
    type Block: Repr<Binary>;

    /// Returns the circuit of the cipher in ECB mode and applies two one-time pads to the output.
    fn ecb_shared() -> Arc<Circuit>;

    /// Returns the circuit of the cipher in counter mode.
    fn ctr() -> Arc<Circuit>;

    /// Returns the circuit of the cipher in counter mode and applies a one-time pad to the output.
    fn ctr_masked() -> Arc<Circuit>;

    /// Returns a one-time pad circuit for decoding the key.
    fn otp() -> Arc<Circuit>;
}
