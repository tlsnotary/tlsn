use std::sync::Arc;

use crate::SHA256_STATE;
use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder},
    circuits::nbit_xor,
    BitOrder, Circuit, ValueType, SHA_256,
};

/// HMAC-SHA256 Pad circuit
///
/// Computes the hash state H(KEY ⊕ PAD) for a given key and pad.
///
/// Inputs:
///
///   0. KEY: N-byte key
///
/// Outputs:
///
///   0. HASH_STATE: 64-byte hash state H(KEY ⊕ PAD)
pub fn hmac_pad(key_len: usize, pad: [u8; 64]) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("SHA256", "", "0.1.0", BitOrder::Msb0);

    let key_bit_len = key_len * 8;

    let key = builder.add_input(
        "KEY",
        &format!("{key_bit_len}-byte key"),
        ValueType::Bytes,
        key_bit_len,
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

    let xor_512_circ = nbit_xor(512);
    let sha256_circ = SHA_256.clone();

    let xor = builder.add_circ(&xor_512_circ);
    let sha256 = builder.add_circ(&sha256_circ);

    let xor_a = xor.input(0).expect("nbit_xor missing input 0");
    let xor_b = xor.input(1).expect("nbit_xor missing input 1");

    map_bytes(
        &mut builder,
        BitOrder::Msb0,
        const_zero[0],
        const_one[0],
        &xor_a[..],
        &pad,
    );
    builder.connect(&key[..], &xor_b[..key_bit_len]);
    builder.connect(
        &vec![const_zero[0]; 512 - key_bit_len],
        &xor_b[key_bit_len..],
    );
    builder.connect(
        &xor.output(0).expect("nbit_xor missing output 0")[..],
        &sha256.input(0).expect("sha256 missing input 0")[..],
    );
    // map SHA256 initial state
    map_bytes(
        &mut builder,
        BitOrder::Msb0,
        const_zero[0],
        const_one[0],
        &sha256.input(1).expect("sha256 missing input 1")[..],
        &SHA256_STATE
            .iter()
            .map(|chunk| chunk.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    );

    let mut builder = builder.build_gates();

    let hash_state = builder.add_output(
        "HASH_STATE",
        "32-byte hash state H(KEY ⊕ PAD)",
        ValueType::Bytes,
        256,
    );

    builder.connect(
        &sha256.output(0).expect("sha256 missing output 0")[..],
        &hash_state[..],
    );

    builder.build_circuit().expect("failed to build hmac_pad")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{partial_sha256_digest, test_circ};
    use mpc_circuits::Value;

    #[test]
    #[ignore = "expensive"]
    fn test_hmac_pad_inner() {
        let key = [69u8; 32];
        let pad = [0x36u8; 64];

        let circ = hmac_pad(32, pad);

        let mut key_padded = [0u8; 64];
        key_padded[..32].copy_from_slice(&key);
        key_padded
            .iter_mut()
            .zip(pad.iter())
            .for_each(|(key, pad)| *key ^= pad);

        let expected_hash_state = partial_sha256_digest(&key_padded);

        test_circ(
            &circ,
            &[Value::Bytes(key.to_vec())],
            &[Value::Bytes(
                expected_hash_state
                    .iter()
                    .copied()
                    .map(|chunk| chunk.to_be_bytes())
                    .flatten()
                    .collect::<Vec<u8>>(),
            )],
        );
    }

    #[test]
    #[ignore = "expensive"]
    fn test_hmac_pad_outer() {
        let key = [69u8; 48];
        let pad = [0x5cu8; 64];

        let circ = hmac_pad(48, pad);

        let mut key_padded = [0u8; 64];
        key_padded[..48].copy_from_slice(&key);
        key_padded
            .iter_mut()
            .zip(pad.iter())
            .for_each(|(key, pad)| *key ^= pad);

        let expected_hash_state = partial_sha256_digest(&key_padded);

        test_circ(
            &circ,
            &[Value::Bytes(key.to_vec())],
            &[Value::Bytes(
                expected_hash_state
                    .iter()
                    .copied()
                    .map(|chunk| chunk.to_be_bytes())
                    .flatten()
                    .collect::<Vec<u8>>(),
            )],
        );
    }
}
