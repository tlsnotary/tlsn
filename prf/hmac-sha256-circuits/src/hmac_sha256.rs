use std::sync::Arc;

use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder},
    circuits::nbit_xor,
    BitOrder, Circuit, ValueType,
};

use crate::sha256;

/// Computes HMAC(k, m).
///
/// Inputs:
///
///   0. KEY: 32-byte key
///   1. MSG: N-byte message
///
/// Outputs:
///
///   0. HASH: 32-byte hash
pub fn hmac_sha256(len: usize) -> Arc<Circuit> {
    let mut builder =
        CircuitBuilder::new(&format!("{len}byte_sha256"), "", "0.1.0", BitOrder::Msb0);

    let key = builder.add_input("KEY", "32-byte key", ValueType::Bytes, 256);
    let msg = builder.add_input(
        "MSG",
        &format!("{len}-byte message"),
        ValueType::Bytes,
        len * 8,
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

    let sha256_inner_circ = sha256(64 + len);
    let sha256_outer_circ = sha256(96);
    let xor_circ = nbit_xor(512);

    let inner_hash_circ = builder.add_circ(&sha256_inner_circ);
    let outer_hash_circ = builder.add_circ(&sha256_outer_circ);
    let xor_ipad = builder.add_circ(&xor_circ);
    let xor_opad = builder.add_circ(&xor_circ);

    // Connect constant wires
    builder.connect(
        &const_zero[..],
        &inner_hash_circ
            .input(1)
            .expect("sha256 should have input 1")[..],
    );
    builder.connect(
        &const_one[..],
        &inner_hash_circ
            .input(2)
            .expect("sha256 should have input 2")[..],
    );
    builder.connect(
        &const_zero[..],
        &outer_hash_circ
            .input(1)
            .expect("sha256 should have input 1")[..],
    );
    builder.connect(
        &const_one[..],
        &outer_hash_circ
            .input(2)
            .expect("sha256 should have input 2")[..],
    );

    let key_ipad = {
        let a = xor_ipad.input(0).expect("xor should have input 0");
        let b = xor_ipad.input(1).expect("xor should have input 1");

        // Connect key wires (32 bytes)
        builder.connect(&key[..], &a[..256]);
        // Connect zero pads (32 bytes)
        builder.connect_fan_out(const_zero[0], &a[256..]);

        // Connect ipad wires
        map_bytes(
            &mut builder,
            BitOrder::Msb0,
            const_zero[0],
            const_one[0],
            &b[..],
            &[0x36; 64],
        );

        xor_ipad.output(0).expect("xor should have output 0")
    };

    let key_opad = {
        let a = xor_opad.input(0).expect("xor should have input 0");
        let b = xor_opad.input(1).expect("xor should have input 1");

        // Connect key wires (32 bytes)
        builder.connect(&key[..], &a[..256]);
        // Connect zero pads (32 bytes)
        builder.connect_fan_out(const_zero[0], &a[256..]);

        // Connect opad wires
        map_bytes(
            &mut builder,
            BitOrder::Msb0,
            const_zero[0],
            const_one[0],
            &b[..],
            &[0x5cu8; 64],
        );

        xor_opad.output(0).expect("xor should have output 0")
    };

    // Compute inner hash
    let inner_hash = {
        let inner_msg = inner_hash_circ
            .input(0)
            .expect("sha256 should have input 0");

        // Connect key wires
        builder.connect(&key_ipad[..], &inner_msg[..512]);
        // Connect msg wires
        builder.connect(&msg[..], &inner_msg[512..]);

        inner_hash_circ
            .output(0)
            .expect("sha256 should have output 0")
    };

    // Compute outer hash
    let outer_hash = {
        let outer_msg = outer_hash_circ
            .input(0)
            .expect("sha256 should have input 0");

        // Connect key wires
        builder.connect(&key_opad[..], &outer_msg[..512]);
        // Connect inner hash wires
        builder.connect(&inner_hash[..], &outer_msg[512..]);

        outer_hash_circ
            .output(0)
            .expect("sha256 should have output 0")
    };

    let mut builder = builder.build_gates();

    let hash = builder.add_output("HASH", "32-byte hash", ValueType::Bytes, 256);

    builder.connect(&outer_hash[..], &hash[..]);

    builder
        .build_circuit()
        .expect("failed to build hmac_sha256")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{partial_sha256_digest, test_circ};
    use mpc_circuits::Value;

    use hmac::{Hmac, Mac};

    #[test]
    #[ignore = "expensive"]
    fn test_hmac_sha256() {
        let key = [69u8; 32];
        let msg = [42u8; 47];

        let circ = hmac_sha256(msg.len());

        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&msg);
        let expected = hmac.finalize().into_bytes().to_vec();

        test_circ(
            &circ,
            &[Value::Bytes(key.to_vec()), Value::Bytes(msg.to_vec())],
            &[Value::Bytes(expected)],
        );
    }

    #[test]
    #[ignore = "expensive"]
    fn test_hmac_sha256_multi_block() {
        let key = [69u8; 32];
        let msg = [42u8; 79];

        let circ = hmac_sha256(msg.len());

        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&msg);
        let expected = hmac.finalize().into_bytes().to_vec();

        test_circ(
            &circ,
            &[Value::Bytes(key.to_vec()), Value::Bytes(msg.to_vec())],
            &[Value::Bytes(expected)],
        );
    }
}
