use std::sync::Arc;

use crate::{builder::CircuitBuilder, circuit::GateType, Circuit, ValueType};

/// Builds a half adder circuit
pub fn half_adder() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("Binary half-adder", "0.1.0");

    let a = builder.add_input("A", "1 bit", ValueType::Bool, 1);
    let b = builder.add_input("B", "1 bit", ValueType::Bool, 1);

    let mut builder = builder.build_inputs();

    let xor = builder.add_gate(GateType::Xor);
    let and = builder.add_gate(GateType::And);

    builder.connect(&[a[0]], &[xor.x()]);
    builder.connect(&[b[0]], &[xor.y().expect("gate should be XOR")]);
    builder.connect(&[a[0]], &[and.x()]);
    builder.connect(&[b[0]], &[and.y().expect("gate should be AND")]);

    let mut builder = builder.build_gates();

    let sum = builder.add_output("SUM", "Sum bit", ValueType::Bool, 1);
    let carry = builder.add_output("CARRY", "Carry bit", ValueType::Bool, 1);

    builder.connect(&[xor.z()], &[sum[0]]);
    builder.connect(&[and.z()], &[carry[0]]);

    builder.build_circuit().expect("Failed to build half_adder")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    #[test]
    fn test_half_adder() {
        let circ = half_adder();
        test_circ(
            &circ,
            &[Value::Bool(false), Value::Bool(false)],
            &[Value::Bool(false), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bool(false), Value::Bool(true)],
            &[Value::Bool(true), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bool(true), Value::Bool(false)],
            &[Value::Bool(true), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bool(true), Value::Bool(true)],
            &[Value::Bool(false), Value::Bool(true)],
        );
    }
}
