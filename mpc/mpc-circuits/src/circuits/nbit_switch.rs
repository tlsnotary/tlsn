use std::sync::Arc;

use crate::{
    builder::{CircuitBuilder, Feed, WireHandle},
    circuit::GateType,
    Circuit, ValueType,
};

/// Builds a switch which toggles between two n-bit numbers
///
/// Outputs A if toggle = 0, else B
pub fn nbit_switch(n: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(
        &format!("{n}BitSwitch"),
        &format!("{n}-bit Binary Switch"),
        "0.1.0",
    );

    let a = builder.add_input("A", &format!("{}-bit number", n), ValueType::Bits, n);
    let b = builder.add_input("B", &format!("{}-bit number", n), ValueType::Bits, n);
    let toggle = builder.add_input("TOGGLE", "Toggle bit", ValueType::Bool, 1);

    let mut builder = builder.build_inputs();

    let toggle_inv_gate = builder.add_gate(GateType::Inv);
    builder.connect(&[toggle[0]], &[toggle_inv_gate.x()]);
    let toggle_inv = toggle_inv_gate.z();

    let switch_outputs: Vec<WireHandle<Feed>> = (0..n)
        .map(|i| {
            let and_a = builder.add_gate(GateType::And);
            let and_b = builder.add_gate(GateType::And);
            let xor = builder.add_gate(GateType::Xor);

            builder.connect(&[a[i]], &[and_a.x()]);
            builder.connect(&[toggle_inv], &[and_a.y().unwrap()]);
            builder.connect(&[b[i]], &[and_b.x()]);
            builder.connect(&[toggle[0]], &[and_b.y().unwrap()]);
            builder.connect(&[and_a.z(), and_b.z()], &[xor.x(), xor.y().unwrap()]);
            xor.z()
        })
        .collect();

    let mut builder = builder.build_gates();
    let out = builder.add_output("OUT", &format!("{}-bit number", n), ValueType::Bits, n);

    switch_outputs
        .into_iter()
        .enumerate()
        .for_each(|(i, feed)| builder.connect(&[feed], &[out[i]]));

    builder
        .build_circuit()
        .expect("failed to build n-bit switch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    #[test]
    fn test_nbit_switch() {
        let circ = nbit_switch(4);
        test_circ(
            &circ,
            &[
                Value::Bits(vec![false; 4]),
                Value::Bits(vec![true; 4]),
                Value::Bool(false),
            ],
            &[Value::Bits(vec![false; 4])],
        );
        test_circ(
            &circ,
            &[
                Value::Bits(vec![false; 4]),
                Value::Bits(vec![true; 4]),
                Value::Bool(true),
            ],
            &[Value::Bits(vec![true; 4])],
        );
        // make sure no funny business with bits switching
        test_circ(
            &circ,
            &[
                Value::Bits(vec![false, true, false, true]),
                Value::Bits(vec![false, true, false, true]),
                Value::Bool(false),
            ],
            &[Value::Bits(vec![false, true, false, true])],
        );
        test_circ(
            &circ,
            &[
                Value::Bits(vec![false, true, true, true]),
                Value::Bits(vec![true, true, false, true]),
                Value::Bool(true),
            ],
            &[Value::Bits(vec![true, true, false, true])],
        );
    }
}
