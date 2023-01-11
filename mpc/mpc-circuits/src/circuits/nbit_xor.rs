use std::sync::Arc;

use crate::{
    builder::{CircuitBuilder, Feed, WireHandle},
    circuit::GateType,
    Circuit, ValueType,
};

/// Builds a circuit which computes XOR of two n-bit inputs
pub fn nbit_xor(n: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(
        &format!("{n}BitXor"),
        &format!("{n}-bit Binary XOR"),
        "0.1.0",
    );

    let a = builder.add_input("A", &format!("{}-bit input", n), ValueType::Bits, n);
    let b = builder.add_input("B", &format!("{}-bit input", n), ValueType::Bits, n);

    let mut builder = builder.build_inputs();

    let gate_outs: Vec<WireHandle<Feed>> = (0..n)
        .map(|i| {
            let xor = builder.add_gate(GateType::Xor);
            builder.connect(&[a[i], b[i]], &[xor.x(), xor.y().unwrap()]);
            xor.z()
        })
        .collect();

    let mut builder = builder.build_gates();
    let out = builder.add_output("OUT", &format!("{}-bit output", n), ValueType::Bits, n);

    builder.connect(&gate_outs, &out[..]);

    builder
        .build_circuit()
        .expect("failed to build n-bit switch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    #[test]
    fn test_nbit_xor() {
        let circ = nbit_xor(8);
        test_circ(
            &circ,
            &[Value::Bits(vec![false; 8]), Value::Bits(vec![true; 8])],
            &[Value::Bits(vec![true; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bits(vec![true; 8]), Value::Bits(vec![false; 8])],
            &[Value::Bits(vec![true; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bits(vec![false; 8]), Value::Bits(vec![false; 8])],
            &[Value::Bits(vec![false; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bits(vec![true; 8]), Value::Bits(vec![true; 8])],
            &[Value::Bits(vec![false; 8])],
        );
    }
}
