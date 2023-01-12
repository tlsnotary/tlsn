use std::sync::Arc;

use crate::{builder::CircuitBuilder, circuit::GateType, Circuit, ValueType};

use super::half_adder;

fn ripple() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("Ripple", "Ripple adder", "");
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

/// Builds an N-bit binary adder
pub fn nbit_adder(n: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(
        &format!("{n}BitAdder"),
        &format!("{n}-bit Binary Adder without Carry-out"),
        "0.1.0",
    );

    let a = builder.add_input("A", &format!("{}-bit number", n), ValueType::Bits, n);
    let b = builder.add_input("B", &format!("{}-bit number", n), ValueType::Bits, n);

    let mut builder = builder.build_inputs();

    let half_adder = builder.add_circ(&half_adder());

    builder.connect(&[a[0]], &[half_adder.input(0).unwrap()[0]]);
    builder.connect(&[b[0]], &[half_adder.input(1).unwrap()[0]]);

    let adder_circ = ripple();
    // add ripple adders for bits 1 to n-1
    let adders: Vec<_> = (1..n - 1).map(|_| builder.add_circ(&adder_circ)).collect();

    // last adder in chain has no c_out
    let final_ab = builder.add_gate(GateType::Xor);
    let final_sum = builder.add_gate(GateType::Xor);

    let mut builder = builder.build_gates();
    let sum = builder.add_output("SUM", &format!("{}-bit number", n), ValueType::Bits, n);

    // connect half-adder sum to sum[0]
    builder.connect(&[half_adder.output(0).unwrap()[0]], &[sum[0]]);
    // connect half-adder c_out into the ripple chain
    builder.connect(
        &[half_adder.output(1).unwrap()[0]],
        &[adders[0].input(2).unwrap()[0]],
    );

    for idx in 0..adders.len() {
        builder.connect(&[a[idx + 1]], &[adders[idx].input(0).unwrap()[0]]);
        builder.connect(&[b[idx + 1]], &[adders[idx].input(1).unwrap()[0]]);
        builder.connect(&[adders[idx].output(0).unwrap()[0]], &[sum[idx + 1]]);
        if idx < adders.len() - 1 {
            // chain carry bits
            builder.connect(
                &[adders[idx].output(1).unwrap()[0]],
                &[adders[idx + 1].input(2).unwrap()[0]],
            );
        }
    }

    // connect c_out from chain into final adder
    builder.connect(
        &[adders[adders.len() - 1].output(1).unwrap()[0]],
        &[final_sum.x()],
    );
    // sum last bits
    builder.connect(&[a[n - 1]], &[final_ab.x()]);
    builder.connect(&[b[n - 1]], &[final_ab.y().unwrap()]);
    builder.connect(&[final_ab.z()], &[final_sum.y().unwrap()]);
    builder.connect(&[final_sum.z()], &[sum[n - 1]]);

    builder
        .build_circuit()
        .expect("failed to build n-bit adder")
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
    fn test_nbit_adder_64() {
        let circ = nbit_adder(64);
        test_circ(
            &circ,
            &[Value::Bits(u64(0)), Value::Bits(u64(0))],
            &[Value::Bits(u64(0))],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(0)), Value::Bits(u64(1))],
            &[Value::Bits(u64(1))],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(1)), Value::Bits(u64(0))],
            &[Value::Bits(u64(1))],
        );
        test_circ(
            &circ,
            &[Value::Bits(u64(1)), Value::Bits(u64(1))],
            &[Value::Bits(u64(2))],
        );
        test_circ(
            &circ,
            &[
                Value::Bits(u64(u64::MAX / 2)),
                Value::Bits(u64(u64::MAX / 3)),
            ],
            &[Value::Bits(u64((u64::MAX / 2) + (u64::MAX / 3)))],
        );
        // bit overflow
        test_circ(
            &circ,
            &[Value::Bits(u64(u64::MAX)), Value::Bits(u64(u64::MAX))],
            &[Value::Bits(u64(u64::MAX << 1))],
        );
        // bit overflow
        test_circ(
            &circ,
            &[Value::Bits(u64(u64::MAX)), Value::Bits(u64(1))],
            &[Value::Bits(u64(0))],
        );
    }

    #[test]
    fn test_nbit_adder_256() {
        let circ = nbit_adder(256);

        let a = vec![false; 256];
        let b = vec![false; 256];
        let c = vec![false; 256];
        test_circ(&circ, &[Value::Bits(a), Value::Bits(b)], &[Value::Bits(c)]);

        let mut a = vec![false; 256];
        a[0] = true;
        let b = vec![false; 256];
        let mut c = vec![false; 256];
        c[0] = true;
        test_circ(&circ, &[Value::Bits(a), Value::Bits(b)], &[Value::Bits(c)]);

        let a = vec![false; 256];
        let mut b = vec![false; 256];
        b[0] = true;
        let mut c = vec![false; 256];
        c[0] = true;
        test_circ(&circ, &[Value::Bits(a), Value::Bits(b)], &[Value::Bits(c)]);

        let mut a = vec![false; 256];
        a[1] = true;
        let b = vec![false; 256];
        let mut c = vec![false; 256];
        c[1] = true;
        test_circ(&circ, &[Value::Bits(a), Value::Bits(b)], &[Value::Bits(c)]);

        let mut a = vec![false; 256];
        a[0] = true;
        let mut b = vec![false; 256];
        b[0] = true;
        let mut c = vec![false; 256];
        c[1] = true;
        test_circ(&circ, &[Value::Bits(a), Value::Bits(b)], &[Value::Bits(c)]);

        // bit overflow
        let a = vec![true; 256];
        let b = vec![true; 256];
        let mut c = vec![true; 256];
        c[0] = false;
        test_circ(&circ, &[Value::Bits(a), Value::Bits(b)], &[Value::Bits(c)]);

        // bit overflow
        let a = vec![true; 256];
        let mut b = vec![false; 256];
        b[0] = true;
        let c = vec![false; 256];
        test_circ(&circ, &[Value::Bits(a), Value::Bits(b)], &[Value::Bits(c)]);
    }
}
