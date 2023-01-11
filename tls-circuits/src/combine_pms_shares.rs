use std::sync::Arc;

use mpc_circuits::{
    builder::{map_le_bytes, CircuitBuilder},
    circuits::nbit_add_mod,
    Circuit, ValueType,
};

/// Combines two PMS shares
///
/// Each share must already be reduced mod P
pub fn combine_pms_shares() -> Arc<Circuit> {
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
    let const_zero = builder.add_input(
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

    let add_mod = builder.add_circ(&nbit_add_mod(256));
    let add_mod_a = add_mod.input(0).expect("add mod is missing input 0");
    let add_mod_b = add_mod.input(1).expect("add mod is missing input 1");
    let add_mod_mod = add_mod.input(2).expect("add mod is missing input 2");
    let add_mod_const_zero = add_mod.input(3).expect("add mod is missing input 3");
    let add_mod_const_one = add_mod.input(4).expect("add mod is missing input 4");
    let add_mod_out = add_mod.output(0).expect("add mod is missing output 0");

    builder.connect(&[const_zero[0]], &[add_mod_const_zero[0]]);
    builder.connect(&[const_one[0]], &[add_mod_const_one[0]]);

    builder.connect(&a[..], &add_mod_a[..]);
    builder.connect(&b[..], &add_mod_b[..]);

    // map p256 prime to mod
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &add_mod_mod[..],
        &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF,
        ],
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
    use super::*;
    use mpc_circuits::{circuits::test_circ, Value};
    use num_bigint::BigUint;
    use num_traits::One;

    /// NIST P-256 Prime
    const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

    #[test]
    #[ignore = "expensive"]
    fn test_combine_pms_shares() {
        let circ = combine_pms_shares();
        let p = BigUint::parse_bytes(P.as_bytes(), 16).unwrap();
        let mut one = vec![0x00; 32];
        one[0] = 1;
        let mut two = vec![0x00; 32];
        two[0] = 2;
        // 0 + 0 mod p = 0
        test_circ(
            &circ,
            &[Value::Bytes(vec![0x00; 32]), Value::Bytes(vec![0x00; 32])],
            &[Value::Bytes(vec![0x00; 32])],
        );
        // 0 + 1 mod p = 1
        test_circ(
            &circ,
            &[Value::Bytes(vec![0x00; 32]), Value::Bytes(one.clone())],
            &[Value::Bytes(one.clone())],
        );
        let a = [vec![255; 16], vec![0; 16]].concat();
        let b = [vec![255; 16], vec![0; 16]].concat();
        let expected = [vec![254], vec![255; 15], vec![1], vec![0; 15]].concat();
        test_circ(
            &circ,
            &[Value::Bytes(a), Value::Bytes(b)],
            &[Value::Bytes(expected)],
        );
        let p_minus_one = p.clone() - BigUint::one();
        // (p + p - 2) mod p = p - 2
        test_circ(
            &circ,
            &[
                Value::Bytes(p_minus_one.to_bytes_le()),
                Value::Bytes(p_minus_one.to_bytes_le()),
            ],
            &[Value::Bytes(
                ((p_minus_one.clone() + p_minus_one) % p.clone()).to_bytes_le(),
            )],
        );
        // (p - 1) + 2 mod p = 1
        test_circ(
            &circ,
            &[
                Value::Bytes((p.clone() - BigUint::one()).to_bytes_le()),
                Value::Bytes(two.clone()),
            ],
            &[Value::Bytes(one.clone())],
        );
        // p + 0 mod p = 0
        test_circ(
            &circ,
            &[Value::Bytes(p.to_bytes_le()), Value::Bytes(vec![0; 32])],
            &[Value::Bytes(vec![0; 32])],
        );
    }
}
