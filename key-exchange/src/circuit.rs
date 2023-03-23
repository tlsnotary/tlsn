//! This module provides the circuits used in the key exchange protocol

use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder},
    circuits::{nbit_add_mod, nbit_xor},
    BitOrder, Circuit, ValueType,
};
use once_cell::sync::Lazy;
use std::sync::Arc;

/// Circuit for combining additive shares of the PMS, twice
///
/// # Inputs
///
/// 0. PMS_SHARE_A: 32 bytes PMS Additive Share
/// 1. PMS_SHARE_B: 32 bytes PMS Additive Share
/// 2. PMS_SHARE_C: 32 bytes PMS Additive Share
/// 3. PMS_SHARE_D: 32 bytes PMS Additive Share
/// 4. CONST_ZERO: 1-bit, must be zero
/// 5. CONST_ONE: 1-bit, must be one
///
/// # Outputs
/// 0. PMS1: Pre-master Secret = PMS_SHARE_A + PMS_SHARE_B
/// 1. PMS2: Pre-master Secret = PMS_SHARE_C + PMS_SHARE_D
pub static COMBINE_PMS: Lazy<Arc<Circuit>> = Lazy::new(build_double_combine_pms_circuit);

/// Circuit for XORing two 32-byte inputs
///
/// # Inputs
/// 0. INPUT_A: 32-byte input
/// 1. INPUT_B: 32-byte input
///
/// # Outputs
/// 0. OUTPUT: 32-byte output = INPUT_A ^ INPUT_B
pub static XOR_BYTES_32: Lazy<Arc<Circuit>> = Lazy::new(build_nbit_xor_bytes_32);

/// Combines two PMS shares
///
/// Each share must already be reduced mod P
pub fn combine_pms_shares() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("pms_shares", "", "0.1.0", BitOrder::Lsb0);

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
    map_bytes(
        &mut builder,
        BitOrder::Lsb0,
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

/// Creates a circuit which adds two P256 field elements, twice
///
/// Input to circuit is (A, B, C, D) and circuit returns (A + B, C + D)
pub(crate) fn build_double_combine_pms_circuit() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("pms_shares_2x", "", "0.1.0", BitOrder::Lsb0);

    let a = builder.add_input(
        "PMS_SHARE_A",
        "32 bytes PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let b = builder.add_input(
        "PMS_SHARE_B",
        "32 bytes PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let c = builder.add_input(
        "PMS_SHARE_C",
        "32 bytes PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let d = builder.add_input(
        "PMS_SHARE_D",
        "32 bytes PMS Additive Share",
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
    let pms_circuit = combine_pms_shares();
    let handle1 = builder.add_circ(&pms_circuit);
    let handle2 = builder.add_circ(&pms_circuit);

    let a_input = handle1
        .input(0)
        .expect("Should be able to get handle for input 0 of first pms circuit");
    let b_input = handle1
        .input(1)
        .expect("Should be able to get handle for input 1 of first pms circuit");
    let c_input = handle1
        .input(2)
        .expect("Should be able to get handle for input 2 of first pms circuit");
    let d_input = handle1
        .input(3)
        .expect("Should be able to get handle for input 3 of first pms circuit");

    let e_input = handle2
        .input(0)
        .expect("Should be able to get handle for input 0 of second pms circuit");
    let f_input = handle2
        .input(1)
        .expect("Should be able to get handle for input 1 of second pms circuit");
    let g_input = handle2
        .input(2)
        .expect("Should be able to get handle for input 2 of second pms circuit");
    let h_input = handle2
        .input(3)
        .expect("Should be able to get handle for input 3 of second pms circuit");

    builder.connect(&a[..], &a_input[..]);
    builder.connect(&b[..], &b_input[..]);
    builder.connect(&const_zero[..], &c_input[..]);
    builder.connect(&const_one[..], &d_input[..]);

    builder.connect(&c[..], &e_input[..]);
    builder.connect(&d[..], &f_input[..]);
    builder.connect(&const_zero[..], &g_input[..]);
    builder.connect(&const_one[..], &h_input[..]);

    let pms1_out = handle1
        .output(0)
        .expect("Should be able to get handle for output 0 of first pms circuit");
    let pms2_out = handle2
        .output(0)
        .expect("Should be able to get handle for output 0 of second pms circuit");

    let mut builder = builder.build_gates();

    let pms1 = builder.add_output("PMS1", "32 bytes Pre-master Secret", ValueType::Bytes, 256);
    let pms2 = builder.add_output("PMS2", "32 bytes Pre-master Secret", ValueType::Bytes, 256);

    builder.connect(&pms1_out[..], &pms1[..]);
    builder.connect(&pms2_out[..], &pms2[..]);

    builder
        .build_circuit()
        .expect("Unable to build pms_shares_2x circuit")
}

/// Creates a circuit which returns XOR of two 32-byte inputs
pub(crate) fn build_nbit_xor_bytes_32() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("32_bytes_xor", "", "0.1.0", BitOrder::Lsb0);

    let a = builder.add_input("PMS_1", "32 bytes Pre-master Secret", ValueType::Bytes, 256);
    let b = builder.add_input("PMS_2", "32 bytes Pre-master Secret", ValueType::Bytes, 256);
    let mut builder = builder.build_inputs();

    let handle = builder.add_circ(&nbit_xor(256));

    let a_input = handle
        .input(0)
        .expect("Should be able to get handle for input 0 of bytes_xor circuit");
    let b_input = handle
        .input(1)
        .expect("Should be able to get handle for input 1 of bytes_xor circuit");

    builder.connect(&a[..], &a_input[..]);
    builder.connect(&b[..], &b_input[..]);

    let pms_xor_out = handle
        .output(0)
        .expect("Should be able to get handle for output 0 of bytes_xor circuit");

    let mut builder = builder.build_gates();

    let pms_xor = builder.add_output("PMS_XOR", "32 bytes XOR of PMS", ValueType::Bytes, 256);

    builder.connect(&pms_xor_out[..], &pms_xor[..]);

    builder
        .build_circuit()
        .expect("Unable to build 32_bytes_xor circuit")
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
