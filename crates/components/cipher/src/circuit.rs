//! Ciphers and circuits.

use mpz_circuits::{types::ValueType, Circuit, CircuitBuilder, Tracer};
use mpz_memory_core::{binary::Binary, Repr, StaticSize};
use std::sync::Arc;

/// A cipher circuit.
pub trait CipherCircuit: Send + Sync + Unpin + 'static {
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

/// Builds a circuit which XORs the provided values.
pub(crate) fn build_xor_circuit(inputs: &[ValueType]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    for input_ty in inputs {
        let input_0 = builder.add_input_by_type(input_ty.clone());
        let input_1 = builder.add_input_by_type(input_ty.clone());

        let input_0 = Tracer::new(builder.state(), input_0);
        let input_1 = Tracer::new(builder.state(), input_1);
        let output = input_0 ^ input_1;
        builder.add_output(output);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}
