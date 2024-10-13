//! Ciphers and circuits.

use mpz_circuits::Circuit;
use mpz_memory_core::{binary::Binary, Repr};
use std::sync::Arc;

/// A cipher circuit.
pub trait Cipher: Default {
    /// The key type.
    type Key: Repr<Binary> + Copy;
    /// The initialization vector type.
    type Iv: Repr<Binary> + Copy;
    /// The explicit nonce type.
    type Nonce: Repr<Binary> + Copy;
    /// The counter type.
    type Counter: Repr<Binary> + Copy;
    /// The block type.
    type Block: Repr<Binary> + Copy;

    /// Returns the circuit of the cipher in ecb mode and applies two one-time pads to the output.
    fn ecb_shared() -> Arc<Circuit>;

    /// Returns the circuit of the cipher in counter mode.
    fn ctr() -> Arc<Circuit>;

    /// Returns the circuit of the cipher in counter mode and applies a one-time pad to the output.
    fn ctr_masked() -> Arc<Circuit>;

    /// Returns a one-time pad circuit for decoding the key.
    fn otp() -> Arc<Circuit>;
}
