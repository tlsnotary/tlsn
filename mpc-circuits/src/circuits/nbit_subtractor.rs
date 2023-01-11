use std::sync::Arc;

use crate::{builder::CircuitBuilder, circuit::GateType, Circuit, ValueType};

use super::{full_adder, nbit_inverter};

fn ripple() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("", "");
    let a = builder.add_input("A", "", ValueType::Bool, 1);
    let b = builder.add_input("B", "", ValueType::Bool, 1);
    let c_in = builder.add_input("C_IN", "Carry-in bit", ValueType::Bool, 1);

    let mut builder = builder.build_inputs();

    let a_b = builder.add_gate(GateType::Xor);
    // C_OUT = C_IN + ((A + C_IN) & (B + C_IN))
    let a_c_in = builder.add_gate(GateType::Xor);
    let b_c_in = builder.add_gate(GateType::Xor);
    let and = builder.add_gate(GateType::And);
    let and_c_in = builder.add_gate(GateType::Xor);

    // SUM = A + B + C_IN
    let sum_gate = builder.add_gate(GateType::Xor);

    let mut builder = builder.build_gates();

    let sum = builder.add_output("SUM", "Sum", ValueType::Bool, 1);
    let c_out = builder.add_output("C_OUT", "Carry-out bit", ValueType::Bool, 1);

    builder.connect(&[a[0]], &[a_b.x()]);
    builder.connect(&[b[0]], &[a_b.y().unwrap()]);

    builder.connect(&[a[0]], &[a_c_in.x()]);
    builder.connect(&[c_in[0]], &[a_c_in.y().unwrap()]);

    builder.connect(&[b[0]], &[b_c_in.x()]);
    builder.connect(&[c_in[0]], &[b_c_in.y().unwrap()]);

    builder.connect(&[a_c_in.z()], &[and.x()]);
    builder.connect(&[b_c_in.z()], &[and.y().unwrap()]);

    builder.connect(&[and.z()], &[and_c_in.x()]);
    builder.connect(&[c_in[0]], &[and_c_in.y().unwrap()]);

    builder.connect(&[and_c_in.z()], &[c_out[0]]);

    builder.connect(&[c_in[0]], &[sum_gate.x()]);
    builder.connect(&[a_b.z()], &[sum_gate.y().unwrap()]);
    builder.connect(&[sum_gate.z()], &[sum[0]]);

    builder
        .build_circuit()
        .expect("failed to build ripple adder")
}

/// Builds an N-bit binary subtractor with carry-out
///
/// C_OUT = 0 if B > A
pub fn nbit_subtractor(n: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(&format!("{}-bit subtractor", n), "0.1.0");

    let a = builder.add_input("A", &format!("{}-bit number", n), ValueType::Bits, n);
    let b = builder.add_input("B", &format!("{}-bit number", n), ValueType::Bits, n);
    let const_1 = builder.add_input("CONST_ONE", "Constant 1 wire", ValueType::ConstOne, 1);

    let mut builder = builder.build_inputs();

    let b_inverter = builder.add_circ(&nbit_inverter(n));
    let b_inv = b_inverter.output(0).expect("b_inverter missing output 0");
    builder.connect(
        &b[..],
        &b_inverter.input(0).expect("b_inverter missing input 0")[..],
    );

    let full_adder = builder.add_circ(&full_adder());

    builder.connect(
        &[a[0]],
        &[full_adder.input(0).expect("full adder missing input 0")[0]],
    );
    builder.connect(
        &[b_inv[0]],
        &[full_adder.input(1).expect("full adder missing input 1")[0]],
    );
    builder.connect(
        &[const_1[0]],
        &[full_adder.input(2).expect("full adder missing input 2")[0]],
    );

    let adder_circ = ripple();
    // add ripple adders for bits 1 to n-1
    let adders: Vec<_> = (1..n).map(|_| builder.add_circ(&adder_circ)).collect();

    let mut builder = builder.build_gates();
    let sum = builder.add_output("SUM", &format!("{}-bit number", n), ValueType::Bits, n);
    let c_out = builder.add_output("C_OUT", "Carry-out", ValueType::Bool, 1);

    // connect half-adder sum to sum[0]
    builder.connect(&[full_adder.output(0).unwrap()[0]], &[sum[0]]);
    // connect half-adder c_out into the ripple chain
    builder.connect(
        &[full_adder.output(1).unwrap()[0]],
        &[adders[0].input(2).unwrap()[0]],
    );

    for idx in 0..adders.len() {
        builder.connect(&[a[idx + 1]], &[adders[idx].input(0).unwrap()[0]]);
        builder.connect(&[b_inv[idx + 1]], &[adders[idx].input(1).unwrap()[0]]);
        builder.connect(&[adders[idx].output(0).unwrap()[0]], &[sum[idx + 1]]);
        if idx < adders.len() - 1 {
            // chain carry bits
            builder.connect(
                &[adders[idx].output(1).unwrap()[0]],
                &[adders[idx + 1].input(2).unwrap()[0]],
            );
        }
    }

    // connect c_out from chain into circuit c_out
    builder.connect(
        &[adders[adders.len() - 1].output(1).unwrap()[0]],
        &[c_out[0]],
    );

    builder
        .build_circuit()
        .expect("failed to build n-bit subtractor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    /// Converts u64 to LSB0 order boolvec
    fn u64(v: u64) -> Vec<bool> {
        (0..64).map(|i| (v >> i & 1) == 1).collect()
    }

    #[test]
    fn test_nbit_subtractor_64() {
        let circ = nbit_subtractor(64);
        test_circ(
            &circ,
            &[Value::Bits(u64(1)), Value::Bits(u64(1))],
            &[Value::Bits(u64(0)), Value::Bool(true)],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(1)), Value::Bits(u64(0))],
            &[Value::Bits(u64(1)), Value::Bool(true)],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(2)), Value::Bits(u64(1))],
            &[Value::Bits(u64(1)), Value::Bool(true)],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(0)), Value::Bits(u64(0))],
            &[Value::Bits(u64(0)), Value::Bool(true)],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(0)), Value::Bits(u64(1))],
            &[Value::Bits(u64(u64::MAX)), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(0)), Value::Bits(u64(1001))],
            &[Value::Bits(u64(u64::MAX - 1000)), Value::Bool(false)],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(u64::MAX)), Value::Bits(u64(u64::MAX))],
            &[Value::Bits(u64(0)), Value::Bool(true)],
        );
    }
}
