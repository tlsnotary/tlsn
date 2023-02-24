//! This module provides the circuits used in the key exchange protocol

use mpc_circuits::{builder::CircuitBuilder, circuits::nbit_xor, Circuit, ValueType};
use once_cell::sync::Lazy;
use std::sync::Arc;
use tls_circuits::combine_pms_shares;

/// Circuit for combining additive shares of the PMS, twice
///
/// # Inputs
///
/// 0. PMS_SHARE_A: 256-bit PMS Additive Share
/// 1. PMS_SHARE_B: 256-bit PMS Additive Share
/// 2. PMS_SHARE_C: 256-bit PMS Additive Share
/// 3. PMS_SHARE_D: 256-bit PMS Additive Share
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

    let const_zero = builder.add_input(
        "const_zero_1",
        "input that is always 0",
        ValueType::ConstZero,
        1,
    );
    let const_one = builder.add_input(
        "const_one_1",
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
        .expect("Unable to get handle for input 0 of first pms circuit");
    let b_input = handle1
        .input(1)
        .expect("Unable to get handle for input 1 of first pms circuit");
    let c_input = handle1
        .input(2)
        .expect("Unable to get handle for input 2 of first pms circuit");
    let d_input = handle1
        .input(3)
        .expect("Unable to get handle for input 3 of first pms circuit");

    let e_input = handle2
        .input(0)
        .expect("Unable to get handle for input 0 of second pms circuit");
    let f_input = handle2
        .input(1)
        .expect("Unable to get handle for input 1 of second pms circuit");
    let g_input = handle2
        .input(2)
        .expect("Unable to get handle for input 2 of second pms circuit");
    let h_input = handle2
        .input(3)
        .expect("Unable to get handle for input 3 of second pms circuit");

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
        .expect("Unable to get handle for output 0 of first pms circuit");
    let pms2_out = handle2
        .output(0)
        .expect("Unable to get handle for output 0 of second pms circuit");

    let mut builder = builder.build_gates();

    let pms1 = builder.add_output("PMS1", "Pre-master Secret", ValueType::Bytes, 256);
    let pms2 = builder.add_output("PMS2", "Pre-master Secret", ValueType::Bytes, 256);

    builder.connect(&pms1_out[..], &pms1[..]);
    builder.connect(&pms2_out[..], &pms2[..]);

    builder
        .build_circuit()
        .expect("Unable to build pms_shares_2x circuit")
}

/// Creates a circuit which returns XOR of two 32-byte inputs
pub(crate) fn build_nbit_xor_bytes_32() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("32_bytes_xor", "", "0.1.0");

    let a = builder.add_input("PMS_1", "256-bit PMS", ValueType::Bytes, 256);
    let b = builder.add_input("PMS_2", "256-bit PMS", ValueType::Bytes, 256);
    let mut builder = builder.build_inputs();

    let handle = builder.add_circ(&nbit_xor(256));

    let a_input = handle
        .input(0)
        .expect("Unable to get handle for input 0 of bytes_xor circuit");
    let b_input = handle
        .input(1)
        .expect("Unable to get handle for input 1 of bytes_xor circuit");

    builder.connect(&a[..], &a_input[..]);
    builder.connect(&b[..], &b_input[..]);

    let pms_xor_out = handle
        .output(0)
        .expect("Unable to get handle for output 0 of bytes_xor circuit");

    let mut builder = builder.build_gates();

    let pms_xor = builder.add_output("PMS_XOR", "XOR of PMS", ValueType::Bytes, 256);

    builder.connect(&pms_xor_out[..], &pms_xor[..]);

    builder
        .build_circuit()
        .expect("Unable to build 32_bytes_xor circuit")
}
