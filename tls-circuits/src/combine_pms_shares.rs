use mpc_circuits::{
    builder::{CircuitBuilder, Feed, Gates, Sink, WireHandle},
    circuits::nbit_add_mod,
    Circuit, ValueType,
};

/// Maps P-256 Prime to sink wires
/// ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
fn p256prime(
    builder: &mut CircuitBuilder<Gates>,
    const_zero: &WireHandle<Feed>,
    const_one: &WireHandle<Feed>,
    sinks: &[WireHandle<Sink>],
) {
    for i in 0..96 {
        builder.connect(&[*const_one], &[sinks[i]]);
    }
    for i in 96..192 {
        builder.connect(&[*const_zero], &[sinks[i]]);
    }
    for i in 192..196 {
        builder.connect(&[*const_one], &[sinks[i]]);
    }
    for i in 196..224 {
        builder.connect(&[*const_zero], &[sinks[i]]);
    }
    for i in 224..256 {
        builder.connect(&[*const_one], &[sinks[i]]);
    }
}

pub fn combine_pms_shares() -> Circuit {
    let mut builder = CircuitBuilder::new("combine_pms_shares", "0.1.0");

    let a = builder.add_input(
        "PMS_SHARE_A",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let b = builder.add_input(
        "PMS_SHARE_B",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let const_zero_0 = builder.add_input(
        "const_zero",
        "input that is always 0",
        ValueType::ConstZero,
        1,
    );
    let const_zero_1 = builder.add_input(
        "const_zero",
        "input that is always 0",
        ValueType::ConstZero,
        1,
    );
    let const_one = builder.add_input(
        "const_one",
        "input that is always 1",
        ValueType::ConstOne,
        1,
    );

    let mut builder = builder.build_inputs();

    let add_mod = builder.add_circ(nbit_add_mod(256));
    let add_mod_a = add_mod.input(0).expect("add mod is missing input 0");
    let add_mod_b = add_mod.input(1).expect("add mod is missing input 1");
    let add_mod_mod = add_mod.input(2).expect("add mod is missing input 2");
    let add_mod_const_zero_0 = add_mod.input(3).expect("add mod is missing input 3");
    let add_mod_const_zero_1 = add_mod.input(4).expect("add mod is missing input 4");
    let add_mod_const_one = add_mod.input(5).expect("add mod is missing input 5");
    let add_mod_out = add_mod.output(0).expect("add mod is missing output 0");

    builder.connect(&[const_zero_0[0]], &[add_mod_const_zero_0[0]]);
    builder.connect(&[const_zero_1[0]], &[add_mod_const_zero_1[0]]);
    builder.connect(&[const_one[0]], &[add_mod_const_one[0]]);

    builder.connect(&a[..], &add_mod_a[..]);
    builder.connect(&b[..], &add_mod_b[..]);
    builder.connect(&a[..], &add_mod_a[..]);
    // map p256 prime to mod
    p256prime(
        &mut builder,
        &const_zero_0[0],
        &const_one[0],
        &add_mod_mod[..],
    );

    let mut builder = builder.build_gates();
    let out = builder.add_output("PMS", "Pre-master Secret", ValueType::Bytes, 256);

    builder.connect(&add_mod_out[..], &out[..]);

    builder
        .build_circuit()
        .expect("failed to build combine_pms_shares")
}

#[cfg(test)]
mod tests {
    use std::ops::Sub;

    use super::*;
    use mpc_circuits::{circuits::test_circ, Value};
    use num_bigint::BigUint;
    use num_traits::One;

    /// NIST P-256 Prime
    const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

    #[test]
    fn test_combine_pms_shares() {
        let circ = combine_pms_shares();
        let p = BigUint::parse_bytes(P.as_bytes(), 16).unwrap();
        let p_bytes = p.to_bytes_le();
        test_circ(
            &circ,
            &[Value::Bytes(vec![0x00; 32]), Value::Bytes(vec![0x00; 32])],
            &[Value::Bytes(vec![0x00; 32])],
        );
        test_circ(
            &circ,
            &[Value::Bytes(vec![0x00; 32]), Value::Bytes(vec![0x01; 32])],
            &[Value::Bytes(vec![0x01; 32])],
        );
        let mut b = BigUint::one().to_bytes_le();
        b.resize(32, 0);
        test_circ(
            &circ,
            &[
                Value::Bytes((p - BigUint::one()).to_bytes_le()),
                Value::Bytes(b.clone()),
            ],
            &[Value::Bytes(b)],
        );
    }
}
