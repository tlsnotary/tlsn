//! This module provides the circuits used in the key exchange protocol

use mpc_circuits::{builder::CircuitBuilder, circuits::nbit_xor, Circuit, ValueType};
use std::sync::Arc;
use tls_circuits::combine_pms_shares;

/// Creates a circuit which performs P256 field additions of two points, twice
///
/// Input to circuit is (A, B, C, D) and circuit returns (A + B, C + D)
pub(crate) fn build_double_combine_pms_circuit() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("pms_shares_2x", "", "0.1.0");

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
    let c = builder.add_input(
        "PMS_SHARE_C",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let d = builder.add_input(
        "PMS_SHARE_D",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );

    let const_zero1 = builder.add_input(
        "const_zero_1",
        "input that is always 0",
        ValueType::ConstZero,
        1,
    );
    let const_one1 = builder.add_input(
        "const_one_1",
        "input that is always 1",
        ValueType::ConstOne,
        1,
    );

    let const_zero2 = builder.add_input(
        "const_zero_2",
        "input that is always 0",
        ValueType::ConstZero,
        1,
    );
    let const_one2 = builder.add_input(
        "const_one_2",
        "input that is always 1",
        ValueType::ConstOne,
        1,
    );

    let mut builder = builder.build_inputs();
    let pms_circuit = combine_pms_shares();
    let handle1 = builder.add_circ(&Arc::clone(&pms_circuit));
    let handle2 = builder.add_circ(&pms_circuit);

    let a_input = handle1.input(0).unwrap();
    let b_input = handle1.input(1).unwrap();
    let c_input = handle1.input(2).unwrap();
    let d_input = handle1.input(3).unwrap();

    let e_input = handle2.input(0).unwrap();
    let f_input = handle2.input(1).unwrap();
    let g_input = handle2.input(2).unwrap();
    let h_input = handle2.input(3).unwrap();

    builder.connect(&a[..], &a_input[..]);
    builder.connect(&b[..], &b_input[..]);
    builder.connect(&const_zero1[..], &c_input[..]);
    builder.connect(&const_one1[..], &d_input[..]);

    builder.connect(&c[..], &e_input[..]);
    builder.connect(&d[..], &f_input[..]);
    builder.connect(&const_zero2[..], &g_input[..]);
    builder.connect(&const_one2[..], &h_input[..]);

    let pms1_out = handle1.output(0).unwrap();
    let pms2_out = handle2.output(0).unwrap();

    let mut builder = builder.build_gates();

    let pms1 = builder.add_output("PMS1", "Pre-master Secret", ValueType::Bytes, 256);
    let pms2 = builder.add_output("PMS2", "Pre-master Secret", ValueType::Bytes, 256);

    builder.connect(&pms1_out[..], &pms1[..]);
    builder.connect(&pms2_out[..], &pms2[..]);

    builder.build_circuit().unwrap()
}

/// Creates a circuit which returns XOR of two 32-byte inputs
pub(crate) fn build_nbit_xor_bytes_32() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("nbit_xor_bytes", "", "0.1.0");

    let a = builder.add_input("PMS_1", "256-bit PMS", ValueType::Bytes, 256);
    let b = builder.add_input("PMS_2", "256-bit PMS", ValueType::Bytes, 256);
    let mut builder = builder.build_inputs();

    let handle = builder.add_circ(&nbit_xor(256));

    let a_input = handle.input(0).unwrap();
    let b_input = handle.input(1).unwrap();

    builder.connect(&a[..], &a_input[..]);
    builder.connect(&b[..], &b_input[..]);

    let pms_xor_out = handle.output(0).unwrap();

    let mut builder = builder.build_gates();

    let pms_xor = builder.add_output("PMS_XOR", "XOR of PMS", ValueType::Bytes, 256);

    builder.connect(&pms_xor_out[..], &pms_xor[..]);

    builder.build_circuit().unwrap()
}
