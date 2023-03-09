use std::sync::Arc;

use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder},
    circuits::nbit_xor,
    BitOrder, Circuit, ValueType,
};

use crate::{sha256, sha256_finalize};

/// Computes HMAC(k, m) using existing key hash states.
///
/// Inputs:
///
///   0. INNER_STATE: 32-byte inner hash state
///   1. OUTER_STATE: 32-byte outer hash state
///   1. MSG: N-byte message
///
/// Outputs:
///
///   0. HASH: 32-byte hash
pub fn hmac_sha256_finalize(len: usize) -> Arc<Circuit> {
    let mut builder =
        CircuitBuilder::new(&format!("{len}byte_sha256"), "", "0.1.0", BitOrder::Msb0);

    let inner_state = builder.add_input(
        "INNER_STATE",
        "32-byte inner hash state",
        ValueType::Bytes,
        256,
    );
    let outer_state = builder.add_input(
        "OUTER_STATE",
        "32-byte outer hash state",
        ValueType::Bytes,
        256,
    );
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

    let sha256_inner_circ = sha256_finalize(64, len);
    let sha256_outer_circ = sha256_finalize(64, 32);

    let inner_hash_circ = builder.add_circ(&sha256_inner_circ);
    let outer_hash_circ = builder.add_circ(&sha256_outer_circ);

    // Connect constant wires
    builder.connect(
        &const_zero[..],
        &inner_hash_circ
            .input(2)
            .expect("sha256_finalize should have input 2")[..],
    );
    builder.connect(
        &const_one[..],
        &inner_hash_circ
            .input(3)
            .expect("sha256_finalize should have input 3")[..],
    );
    builder.connect(
        &const_zero[..],
        &outer_hash_circ
            .input(2)
            .expect("sha256_finalize should have input 2")[..],
    );
    builder.connect(
        &const_one[..],
        &outer_hash_circ
            .input(3)
            .expect("sha256_finalize should have input 3")[..],
    );

    // Compute inner hash
    let inner_hash = {
        // Connect msg wires
        builder.connect(
            &msg[..],
            &inner_hash_circ
                .input(0)
                .expect("sha256_finalize should have input 0")[..],
        );
        // Connect state wires
        builder.connect(
            &inner_state[..],
            &inner_hash_circ
                .input(1)
                .expect("sha256_finalize should have input 1")[..],
        );

        inner_hash_circ
            .output(0)
            .expect("sha256_finalize should have output 0")
    };

    // Compute outer hash
    let outer_hash = {
        // Connect inner hash wires
        builder.connect(
            &inner_hash[..],
            &outer_hash_circ
                .input(0)
                .expect("sha256_finalize should have input 0")[..],
        );
        // Connect state wires
        builder.connect(
            &outer_state[..],
            &outer_hash_circ
                .input(1)
                .expect("sha256_finalize should have input 1")[..],
        );

        outer_hash_circ
            .output(0)
            .expect("sha256_finalize should have output 0")
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
    fn test_hmac_sha256_finalize() {
        let key = [69u8; 32];
        let msg = [42u8; 47];

        let circ = hmac_sha256_finalize(msg.len());

        let key_ipad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x36u8)
            .collect::<Vec<_>>();

        let key_opad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x5cu8)
            .collect::<Vec<_>>();

        let inner_hash_state = partial_sha256_digest(&key_ipad);
        let outer_hash_state = partial_sha256_digest(&key_opad);

        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&msg);
        let expected = hmac.finalize().into_bytes().to_vec();

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    inner_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(
                    outer_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(msg.to_vec()),
            ],
            &[Value::Bytes(expected)],
        );
    }

    #[test]
    #[ignore = "expensive"]
    fn test_hmac_sha256_finalize_multi_block() {
        let key = [69u8; 32];
        let msg = [42u8; 79];

        let circ = hmac_sha256_finalize(msg.len());

        let key_ipad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x36u8)
            .collect::<Vec<_>>();

        let key_opad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x5cu8)
            .collect::<Vec<_>>();

        let inner_hash_state = partial_sha256_digest(&key_ipad);
        let outer_hash_state = partial_sha256_digest(&key_opad);

        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&msg);
        let expected = hmac.finalize().into_bytes().to_vec();

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    inner_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(
                    outer_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(msg.to_vec()),
            ],
            &[Value::Bytes(expected)],
        );
    }
}
