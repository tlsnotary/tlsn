use std::sync::Arc;

use mpc_circuits::{
    builder::{CircuitBuilder, Feed, Gates, WireHandle},
    BitOrder, Circuit, ValueType, SHA_256,
};
use utils::bits::{IterToBits, ToBits};

use crate::SHA256_STATE;

/// Computes SHA-256 compression function
///
/// # Arguments
///
/// * `builder` - Mutable reference to the circuit builder
/// * `msg` - 512-bit message
/// * `initial_state` - 256-bit initial SHA256 state
///
/// # Returns
///
/// * `output_state` - 256-bit output state
pub fn add_sha256_compress(
    builder: &mut CircuitBuilder<Gates>,
    msg: &[WireHandle<Feed>],
    initial_state: &[WireHandle<Feed>],
) -> Vec<WireHandle<Feed>> {
    let sha256 = builder.add_circ(&SHA_256);

    let msg_input = sha256.input(0).expect("sha256 missing input 0");
    let state_input = sha256.input(1).expect("sha256 missing input 1");

    builder.connect(msg, &msg_input[..]);
    builder.connect(initial_state, &state_input[..]);

    let output_state = sha256.output(0).expect("sha256 missing output 0")[..].to_vec();

    output_state
}

/// Computes SHA-256 hash of an arbitrary length message
///
/// # Arguments
///
/// * `builder` - Mutable reference to the circuit builder
/// * `msg` - Arbitrary length message
/// * `initial_state` - 256-bit initial SHA256 state
/// * `const_zero` - 1-bit constant zero
/// * `const_one` - 1-bit constant one
/// * `start_pos` - The number of bytes already processed in the initial state
///
/// # Returns
///
/// * `hash` - 256-bit SHA256 hash
pub fn add_sha256_finalize(
    builder: &mut CircuitBuilder<Gates>,
    msg: &[WireHandle<Feed>],
    initial_state: &[WireHandle<Feed>],
    const_zero: &WireHandle<Feed>,
    const_one: &WireHandle<Feed>,
    start_pos: usize,
) -> Vec<WireHandle<Feed>> {
    // begin with the original message of length L bits
    // append a single '1' bit
    // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    // such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> , (the number of bits will be a multiple of 512)

    let bit_len = msg.len();
    let processed_bit_len = (bit_len + (start_pos * 8)) as u64;

    // K length
    let zero_pad_len = 512 - ((bit_len + 65) % 512);

    let mut padded_msg: Vec<WireHandle<Feed>> = Vec::with_capacity(bit_len + 65 + zero_pad_len);

    padded_msg.extend(&msg[..]);
    // append a single '1' bit
    padded_msg.push(*const_one);
    // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    padded_msg.extend(vec![*const_zero; zero_pad_len]);
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    padded_msg.extend(processed_bit_len.into_msb0_iter().map(|bit| {
        if bit {
            *const_one
        } else {
            *const_zero
        }
    }));

    debug_assert!(padded_msg.len() % 512 == 0);

    let hash = padded_msg
        .chunks(512)
        .fold(initial_state.to_vec(), |state, msg| {
            add_sha256_compress(builder, &msg[..], &state[..])
        });

    hash
}

/// Computes a SHA256 hash of an arbitrary length message.
///
/// Inputs:
///
///   0. MSG: N-byte message
///
/// Outputs:
///
///   0. HASH: 32-byte SHA2 hash
///
/// Arguments:
///
///  * `len`: The number of bytes to hash
pub fn sha256(len: usize) -> Arc<Circuit> {
    let mut builder =
        CircuitBuilder::new(&format!("{len}byte_sha256"), "", "0.1.0", BitOrder::Msb0);

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

    let initial_state = SHA256_STATE
        .into_msb0_iter()
        .map(|bit| if bit { const_one[0] } else { const_zero[0] })
        .collect::<Vec<_>>();

    let hash = add_sha256_finalize(
        &mut builder,
        &msg[..],
        &initial_state,
        &const_zero[0],
        &const_one[0],
        0,
    );

    let mut builder = builder.build_gates();

    let hash_output = builder.add_output("HASH", "32-byte SHA2 hash", ValueType::Bytes, 256);

    builder.connect(&hash, &hash_output[..]);

    builder
        .build_circuit()
        .expect("failed to build sha256_finalize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_circ;
    use mpc_circuits::Value;
    use sha2::{Digest, Sha256};

    #[test]
    #[ignore = "expensive"]
    fn test_sha256() {
        let msg = [69u8; 100];

        let circ = sha256(msg.len());

        let mut hasher = Sha256::new();
        hasher.update(msg);
        let expected = hasher.finalize().to_vec();

        test_circ(
            &circ,
            &[Value::Bytes(msg.to_vec())],
            &[Value::Bytes(expected)],
        );
    }
}
