use std::sync::Arc;

use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder, Feed, Gates, WireHandle},
    circuits::nbit_xor,
    BitOrder, Circuit, ValueType,
};
use utils::bits::IterToBits;

use crate::{add_sha256_compress, add_sha256_finalize};
use hmac_sha256_utils::SHA256_INITIAL_STATE;

/// Computes the outer and inner states of HMAC-SHA256.
///
/// Outer state is H(key ⊕ opad)
///
/// Inner state is H(key ⊕ ipad)
///
/// # Arguments
///
/// * `builder` - Mutable reference to the circuit builder
/// * `key` - N-byte key (must be <= 64 bytes)
/// * `const_zero` - 1-bit constant zero
/// * `const_one` - 1-bit constant one
///
/// # Returns
///
/// * `outer_state` - 256-bit outer state
/// * `inner_state` - 256-bit inner state
pub fn add_hmac_sha256_partial(
    builder: &mut CircuitBuilder<Gates>,
    key: &[WireHandle<Feed>],
    const_zero: &WireHandle<Feed>,
    const_one: &WireHandle<Feed>,
) -> (Vec<WireHandle<Feed>>, Vec<WireHandle<Feed>>) {
    let xor_circ = nbit_xor(512);

    let xor_opad = builder.add_circ(&xor_circ);
    let xor_ipad = builder.add_circ(&xor_circ);

    let key_opad = {
        let a = xor_opad.input(0).expect("xor should have input 0");
        let b = xor_opad.input(1).expect("xor should have input 1");

        // Connect key wires
        builder.connect(key, &a[..key.len()]);
        // Connect zero pads
        builder.connect_fan_out(*const_zero, &a[key.len()..]);

        // Connect opad wires
        map_bytes(
            builder,
            BitOrder::Msb0,
            *const_zero,
            *const_one,
            &b[..],
            &[0x5cu8; 64],
        );

        xor_opad.output(0).expect("xor should have output 0")
    };

    let key_ipad = {
        let a = xor_ipad.input(0).expect("xor should have input 0");
        let b = xor_ipad.input(1).expect("xor should have input 1");

        // Connect key wires
        builder.connect(key, &a[..key.len()]);
        // Connect zero pads
        builder.connect_fan_out(*const_zero, &a[key.len()..]);

        // Connect ipad wires
        map_bytes(
            builder,
            BitOrder::Msb0,
            *const_zero,
            *const_one,
            &b[..],
            &[0x36; 64],
        );

        xor_ipad.output(0).expect("xor should have output 0")
    };

    let sha256_initial_state = SHA256_INITIAL_STATE
        .into_msb0_iter()
        .map(|bit| if bit { *const_one } else { *const_zero })
        .collect::<Vec<_>>();

    let outer_state = add_sha256_compress(builder, &key_opad[..], &sha256_initial_state);
    let inner_state = add_sha256_compress(builder, &key_ipad[..], &sha256_initial_state);

    (outer_state, inner_state)
}

/// Computes HMAC(k, m) using existing key hash states.
///
/// # Inputs
///
/// * `builder` - Mutable reference to the circuit builder
/// * `outer_state` - 256-bit outer hash state
/// * `inner_state` - 256-bit inner hash state
/// * `msg` - Arbitrary length message
/// * `const_zero` - 1-bit constant zero
/// * `const_one` - 1-bit constant one
///
/// # Returns
///
/// * `hash` - 256-bit HMAC-SHA256 hash
pub fn add_hmac_sha256_finalize(
    builder: &mut CircuitBuilder<Gates>,
    outer_state: &[WireHandle<Feed>],
    inner_state: &[WireHandle<Feed>],
    msg: &[WireHandle<Feed>],
    const_zero: &WireHandle<Feed>,
    const_one: &WireHandle<Feed>,
) -> Vec<WireHandle<Feed>> {
    let inner_hash = add_sha256_finalize(builder, msg, inner_state, const_zero, const_one, 64);
    let outer_hash =
        add_sha256_finalize(builder, &inner_hash, outer_state, const_zero, const_one, 64);

    outer_hash
}

/// Computes HMAC(k, m) using existing key hash states.
///
/// # Inputs
///
///   0. OUTER_STATE: 32-byte outer hash state
///   1. INNER_STATE: 32-byte inner hash state
///   2. MSG: N-byte message
///
/// # Outputs
///
///   0. HASH: 32-byte hash
pub fn hmac_sha256_finalize(len: usize) -> Arc<Circuit> {
    let mut builder =
        CircuitBuilder::new(&format!("{len}byte_sha256"), "", "0.1.0", BitOrder::Msb0);

    let outer_state = builder.add_input(
        "OUTER_STATE",
        "32-byte outer hash state",
        ValueType::Bytes,
        256,
    );
    let inner_state = builder.add_input(
        "INNER_STATE",
        "32-byte inner hash state",
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

    let hash = add_hmac_sha256_finalize(
        &mut builder,
        &outer_state[..],
        &inner_state[..],
        &msg[..],
        &const_zero[0],
        &const_one[0],
    );

    let mut builder = builder.build_gates();

    let hash_output = builder.add_output("HASH", "32-byte hash", ValueType::Bytes, 256);

    builder.connect(&hash[..], &hash_output[..]);

    builder
        .build_circuit()
        .expect("failed to build hmac_sha256")
}

#[cfg(test)]
mod tests {
    use super::*;

    use hmac_sha256_utils::{hmac, partial_sha256_digest};
    use mpc_circuits::{circuits::test_circ, Value};

    #[test]
    #[ignore = "expensive"]
    fn test_hmac_sha256_finalize() {
        let key = [69u8; 32];
        let msg = [42u8; 47];

        let circ = hmac_sha256_finalize(msg.len());

        let key_opad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x5cu8)
            .collect::<Vec<_>>();

        let key_ipad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x36u8)
            .collect::<Vec<_>>();

        let outer_hash_state = partial_sha256_digest(&key_opad);
        let inner_hash_state = partial_sha256_digest(&key_ipad);

        let expected = hmac(&key, &msg);

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    outer_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(
                    inner_hash_state
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

        let key_opad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x5cu8)
            .collect::<Vec<_>>();

        let key_ipad = key
            .iter()
            .chain(&[0u8; 32])
            .map(|k| k ^ 0x36u8)
            .collect::<Vec<_>>();

        let outer_hash_state = partial_sha256_digest(&key_opad);
        let inner_hash_state = partial_sha256_digest(&key_ipad);

        let expected = hmac(&key, &msg);

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    outer_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(
                    inner_hash_state
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
