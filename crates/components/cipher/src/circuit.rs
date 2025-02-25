//! Ciphers and circuits.

use mpz_circuits::{types::ValueType, Circuit, CircuitBuilder, Tracer};
use std::sync::Arc;

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
