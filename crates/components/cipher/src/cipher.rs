//! Ciphers and circuits.

use mpz_circuits::Circuit;
use mpz_memory_core::{binary::Binary, Repr, StaticSize};
use std::sync::Arc;

/// A cipher circuit.
pub trait CipherCircuit {
    /// The key type.
    type Key: Repr<Binary> + Copy + StaticSize<Binary>;
    /// The initialization vector type.
    type Iv: Repr<Binary> + Copy + StaticSize<Binary>;
    /// The explicit nonce type.
    type Nonce: Repr<Binary> + Copy + StaticSize<Binary>;
    /// The counter type.
    type Counter: Repr<Binary> + Copy + StaticSize<Binary>;
    /// The block type.
    type Block: Repr<Binary> + Copy + StaticSize<Binary>;

    /// Returns the circuit of the cipher in ecb mode.
    fn ecb() -> Arc<Circuit>;

    /// Returns the circuit of the cipher in counter mode.
    fn ctr() -> Arc<Circuit>;
}