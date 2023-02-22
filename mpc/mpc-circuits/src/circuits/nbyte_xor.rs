use std::sync::Arc;

use crate::{
    builder::{CircuitBuilder, Feed, WireHandle},
    circuit::GateType,
    BitOrder, Circuit, ValueType,
};

/// Builds a circuit which computes XOR of two n-byte inputs
pub fn nbyte_xor(n: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(
        &format!("{n}ByteXor"),
        &format!("{n}-byte Binary XOR, MSB0 bit-order"),
        "0.1.0",
        BitOrder::Msb0,
    );

    let a = builder.add_input("A", &format!("{}-byte input", n), ValueType::Bytes, n * 8);
    let b = builder.add_input("B", &format!("{}-byte input", n), ValueType::Bytes, n * 8);

    let mut builder = builder.build_inputs();

    let gate_outs: Vec<WireHandle<Feed>> = (0..n * 8)
        .map(|i| {
            let xor = builder.add_gate(GateType::Xor);
            builder.connect(&[a[i], b[i]], &[xor.x(), xor.y().unwrap()]);
            xor.z()
        })
        .collect();

    let mut builder = builder.build_gates();
    let out = builder.add_output(
        "OUT",
        &format!("{}-byte output", n),
        ValueType::Bytes,
        n * 8,
    );

    builder.connect(&gate_outs, &out[..]);

    builder.build_circuit().expect("failed to build n-byte xor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    #[test]
    fn test_nbyte_xor() {
        let circ = nbyte_xor(8);
        test_circ(
            &circ,
            &[Value::Bytes(vec![0u8; 8]), Value::Bytes(vec![1u8; 8])],
            &[Value::Bytes(vec![1u8; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bytes(vec![1u8; 8]), Value::Bytes(vec![0u8; 8])],
            &[Value::Bytes(vec![1u8; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bytes(vec![0u8; 8]), Value::Bytes(vec![0u8; 8])],
            &[Value::Bytes(vec![0u8; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bytes(vec![1u8; 8]), Value::Bytes(vec![1u8; 8])],
            &[Value::Bytes(vec![0u8; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bytes(vec![255u8; 8]), Value::Bytes(vec![1u8; 8])],
            &[Value::Bytes(vec![254u8; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bytes(vec![1u8; 8]), Value::Bytes(vec![2u8; 8])],
            &[Value::Bytes(vec![3u8; 8])],
        );
    }
}
