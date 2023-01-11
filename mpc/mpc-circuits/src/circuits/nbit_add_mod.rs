use std::sync::Arc;

use crate::{builder::CircuitBuilder, Circuit, ValueType};

use super::{nbit_adder, nbit_subtractor, nbit_switch};

/// Adds two n-bit numbers modulo another n-bit number
///
/// **NOTE** A and B must already be < MOD
pub fn nbit_add_mod(n: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(
        &format!("{n}BitAddMod"),
        &format!("{n} bit modular addition"),
        "0.1.0",
    );
    let a = builder.add_input("A", &format!("{}_bit number", n), ValueType::Bits, n);
    let b = builder.add_input("B", &format!("{}_bit number", n), ValueType::Bits, n);
    let modulo = builder.add_input(
        "MOD",
        &format!("{}_bit number modulo", n),
        ValueType::Bits,
        n,
    );
    let const_zero = builder.add_input("CONST_ZERO", "Constant 0 bit", ValueType::ConstZero, 1);
    let const_one = builder.add_input("CONST_ONE", "Constant 1 bit", ValueType::ConstOne, 1);

    let mut builder = builder.build_inputs();

    // adder has n + 1 bits to handle overflow
    let adder = builder.add_circ(&nbit_adder(n + 1));
    let adder_in_0 = adder.input(0).expect("adder missing input 0");
    let adder_in_1 = adder.input(1).expect("adder missing input 1");
    builder.connect(&a[..], &adder_in_0[..n]);
    builder.connect(&[const_zero[0]], &[adder_in_0[n]]);
    builder.connect(&b[..], &adder_in_1[..n]);
    builder.connect(&[const_zero[0]], &[adder_in_1[n]]);

    let adder_sum = adder.output(0).expect("adder missing output 0");

    // subtractor computes (A+B) - MOD, C_OUT = 0 if MOD > (A+B)
    let sub = builder.add_circ(&nbit_subtractor(n + 1));
    let sub_in_0 = sub.input(0).expect("subtractor missing input 0");
    let sub_in_1 = sub.input(1).expect("subtractor missing input 1");
    let sub_in_const_one = sub.input(2).expect("subtractor missing input 2");
    builder.connect(&adder_sum[..], &sub_in_0[..]);
    builder.connect(&modulo[..], &sub_in_1[..n]);
    builder.connect(&[const_zero[0]], &[sub_in_1[n]]);
    builder.connect(&[const_one[0]], &[sub_in_const_one[0]]);

    let sub_out = sub.output(0).expect("subtractor missing output 0");
    // this eq 0 if MOD > (A+B)
    let sub_c_out = sub.output(1).expect("subtractor missing output 1");

    // build a switch that returns: if MOD > (A+B) { A + B } else { A + B - MOD }
    let switch = builder.add_circ(&nbit_switch(n));
    let switch_a = switch.input(0).expect("switch is missing input 0");
    let switch_b = switch.input(1).expect("switch is missing input 1");
    let toggle = switch.input(2).expect("switch is missing input 2");
    let switch_out = switch.output(0).expect("switch is missing output 0");
    builder.connect(&[sub_c_out[0]], &[toggle[0]]);
    builder.connect(&adder_sum[..n], &switch_a[..]);
    builder.connect(&sub_out[..n], &switch_b[..]);

    let mut builder = builder.build_gates();

    let out = builder.add_output("OUT", &format!("{}_bit number", n), ValueType::Bits, n);
    builder.connect(&switch_out[..], &out[..]);

    builder
        .build_circuit()
        .expect("failed to build n-bit add mod")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    fn u8(v: u8) -> Vec<bool> {
        (0..8).map(|n| (v >> n & 1) == 1).collect()
    }

    #[test]
    fn test_add_mod() {
        let circ = nbit_add_mod(8);
        // 0 + 0 mod 1 = 0
        test_circ(
            &circ,
            &[Value::Bits(u8(0)), Value::Bits(u8(0)), Value::Bits(u8(1))],
            &[Value::Bits(u8(0))],
        );
        // 0 + 1 mod 1 = 0
        test_circ(
            &circ,
            &[Value::Bits(u8(0)), Value::Bits(u8(1)), Value::Bits(u8(1))],
            &[Value::Bits(u8(0))],
        );
        // 1 + 0 mod 1 = 0
        test_circ(
            &circ,
            &[Value::Bits(u8(1)), Value::Bits(u8(0)), Value::Bits(u8(1))],
            &[Value::Bits(u8(0))],
        );
        // 1 + 1 mod 2 = 0
        test_circ(
            &circ,
            &[Value::Bits(u8(1)), Value::Bits(u8(1)), Value::Bits(u8(2))],
            &[Value::Bits(u8(0))],
        );
        // 1 + 0 mod 2 = 1
        test_circ(
            &circ,
            &[Value::Bits(u8(1)), Value::Bits(u8(0)), Value::Bits(u8(2))],
            &[Value::Bits(u8(1))],
        );
        // 3 + 2 mod 3 = 2
        test_circ(
            &circ,
            &[Value::Bits(u8(3)), Value::Bits(u8(2)), Value::Bits(u8(3))],
            &[Value::Bits(u8(2))],
        );
        // 254 + 1 mod 255 = 0
        test_circ(
            &circ,
            &[
                Value::Bits(u8(u8::MAX - 1)),
                Value::Bits(u8(1)),
                Value::Bits(u8(u8::MAX)),
            ],
            &[Value::Bits(u8(0))],
        );
        // 253 + 253 mod 254 = 252
        test_circ(
            &circ,
            &[
                Value::Bits(u8(u8::MAX - 2)),
                Value::Bits(u8(u8::MAX - 2)),
                Value::Bits(u8(u8::MAX - 1)),
            ],
            &[Value::Bits(u8(u8::MAX - 3))],
        );
    }
}
