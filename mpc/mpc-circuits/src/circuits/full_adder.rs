use std::sync::Arc;

use crate::{builder::CircuitBuilder, circuit::GateType, Circuit, ValueType};

use super::half_adder;

/// Builds a full adder circuit
pub fn full_adder() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("FullAdder", "Binary full-adder", "0.1.0");

    let a = builder.add_input("A", "1 bit", ValueType::Bool, 1);
    let b = builder.add_input("B", "1 bit", ValueType::Bool, 1);
    let c_in = builder.add_input("C_IN", "Carry-in bit", ValueType::Bool, 1);

    let mut builder = builder.build_inputs();

    let half_circ = half_adder();

    let half_1 = builder.add_circ(&half_circ);
    let half_2 = builder.add_circ(&half_circ);
    let xor = builder.add_gate(GateType::Xor);

    builder.connect(&[a[0]], &half_1.input(0).unwrap()[..]);
    builder.connect(&[b[0]], &half_1.input(1).unwrap()[..]);
    builder.connect(
        &half_1.output(0).unwrap()[..],
        &half_2.input(0).unwrap()[..],
    );
    builder.connect(&[c_in[0]], &half_2.input(1).unwrap()[..]);
    builder.connect(&half_2.output(1).unwrap()[..], &[xor.x()]);
    builder.connect(
        &half_1.output(1).unwrap()[..],
        &[xor.y().expect("gate should be XOR")],
    );

    let mut builder = builder.build_gates();

    let sum = builder.add_output("SUM", "Sum bit", ValueType::Bool, 1);
    let c_out = builder.add_output("C_OUT", "Carry-out bit", ValueType::Bool, 1);

    builder.connect(&half_2.output(0).unwrap()[..], &[sum[0]]);
    builder.connect(&[xor.z()], &[c_out[0]]);

    builder.build_circuit().expect("Failed to build full_adder")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    #[test]
    fn test_full_adder() {
        let circ = full_adder();
        test_circ(
            &circ,
            &[Value::Bool(false), Value::Bool(false), Value::Bool(false)],
            &[Value::Bool(false), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bool(false), Value::Bool(true), Value::Bool(false)],
            &[Value::Bool(true), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bool(true), Value::Bool(false), Value::Bool(false)],
            &[Value::Bool(true), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bool(true), Value::Bool(true), Value::Bool(false)],
            &[Value::Bool(false), Value::Bool(true)],
        );
        test_circ(
            &circ,
            &[Value::Bool(false), Value::Bool(false), Value::Bool(true)],
            &[Value::Bool(true), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bool(true), Value::Bool(false), Value::Bool(true)],
            &[Value::Bool(false), Value::Bool(true)],
        );
        test_circ(
            &circ,
            &[Value::Bool(false), Value::Bool(true), Value::Bool(true)],
            &[Value::Bool(false), Value::Bool(true)],
        );
        test_circ(
            &circ,
            &[Value::Bool(true), Value::Bool(true), Value::Bool(true)],
            &[Value::Bool(true), Value::Bool(true)],
        );
    }
}
