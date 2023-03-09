use std::sync::Arc;

use mpc_circuits::{
    builder::{CircuitBuilder, Feed, Gates, SubOutputHandle, WireHandle},
    BitOrder, Circuit, ValueType, SHA_256,
};

/// Finalizes a SHA256 hash
///
/// Inputs:
///
///   0. MSG: N-byte message
///   1. INITIAL_STATE: 32-byte initial SHA2 state
///
/// Outputs:
///
///   0. HASH: 32-byte SHA2 hash
///
/// Arguments:
///
///  * `start_pos`: The number of bytes already processed
///  * `len`: The number of bytes to process
pub fn sha256_finalize(start_pos: usize, len: usize) -> Arc<Circuit> {
    let bit_len = len * 8;
    // K
    let zero_pad_len = 512 - ((bit_len + 65) % 512);

    let total_len = bit_len + 65 + zero_pad_len;

    let mut builder =
        CircuitBuilder::new(&format!("{len}byte_sha256"), "", "0.1.0", BitOrder::Msb0);

    let msg = builder.add_input(
        "MSG",
        &format!("{len}-byte message"),
        ValueType::Bytes,
        bit_len,
    );
    let initial_state = builder.add_input(
        "INITIAL_STATE",
        "32-byte initial SHA2 state",
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

    let sha256_circ = SHA_256.clone();

    let l = (start_pos * 8 + bit_len) as u64;
    let len_pad = l
        .to_be_bytes()
        .iter()
        .map(|byte| {
            (0..8)
                .rev()
                .map(|i| {
                    if (byte >> i & 1) == 1 {
                        const_one[0]
                    } else {
                        const_zero[0]
                    }
                })
                .collect::<Vec<WireHandle<Feed>>>()
        })
        .flatten()
        .collect::<Vec<WireHandle<Feed>>>();

    let mut padded_msg: Vec<WireHandle<Feed>> = Vec::with_capacity(total_len);

    padded_msg.extend(&msg[..]);
    // append a single '1' bit
    padded_msg.push(const_one[0]);
    // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    padded_msg.extend(vec![const_zero[0]; zero_pad_len]);
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    padded_msg.extend(&len_pad);

    fn sha256_compress(
        builder: &mut CircuitBuilder<Gates>,
        circ: &Circuit,
        msg: &[WireHandle<Feed>],
        initial_state: &[WireHandle<Feed>],
    ) -> SubOutputHandle {
        let sha256 = builder.add_circ(circ);

        let chunk = sha256.input(0).expect("sha256 missing input 0");
        let state = sha256.input(1).expect("sha256 missing input 1");

        builder.connect(msg, &chunk[..]);
        builder.connect(initial_state, &state[..]);

        sha256.output(0).expect("sha256 missing output 0")
    }

    let state = padded_msg
        .chunks(512)
        .fold(initial_state[..].to_vec(), |state, msg| {
            sha256_compress(&mut builder, &sha256_circ, &msg[..], &state[..])[..].to_vec()
        });

    let mut builder = builder.build_gates();

    let hash = builder.add_output("HASH", "32-byte SHA2 hash", ValueType::Bytes, 256);

    builder.connect(&state[..], &hash[..]);

    builder
        .build_circuit()
        .expect("failed to build sha256_finalize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{partial_sha256_digest, test_circ};
    use mpc_circuits::Value;
    use sha2::{Digest, Sha256};

    #[test]
    #[ignore = "expensive"]
    fn test_sha256_finalize() {
        let msg = b"client finished00000000000222222222222222222000000000000000000000";

        let circ = sha256_finalize(64, msg.len());

        let ms = [69u8; 48];
        let mut ms_padded = [0u8; 64];
        ms_padded[..48].copy_from_slice(&ms);

        let ms_ipad = ms_padded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        let ms_inner_hash_state = partial_sha256_digest(&ms_ipad);

        let mut hasher = Sha256::new();
        hasher.update(&ms_ipad);
        hasher.update(msg);
        let expected = hasher.finalize().to_vec();

        test_circ(
            &circ,
            &[
                Value::Bytes(msg.to_vec()),
                Value::Bytes(
                    ms_inner_hash_state
                        .into_iter()
                        .map(|v| v.to_be_bytes())
                        .flatten()
                        .collect::<Vec<u8>>(),
                ),
            ],
            &[Value::Bytes(expected)],
        );
    }
}
