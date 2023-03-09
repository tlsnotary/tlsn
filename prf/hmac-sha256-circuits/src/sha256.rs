use std::sync::Arc;

use mpc_circuits::{
    builder::{CircuitBuilder, Feed, Gates, SubOutputHandle, WireHandle},
    BitOrder, Circuit, ValueType, SHA_256,
};
use utils::bits::BytesToBits;

use crate::SHA256_STATE;

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

    let sha256_compress_circ = SHA_256.clone();

    let mut padded_msg: Vec<WireHandle<Feed>> = Vec::with_capacity(total_len);

    padded_msg.extend(&msg[..]);
    // append a single '1' bit
    padded_msg.push(const_one[0]);
    // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    padded_msg.extend(vec![const_zero[0]; zero_pad_len]);
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    padded_msg.extend((bit_len as u64).to_be_bytes().into_msb0_iter().map(|bit| {
        if bit {
            const_one[0]
        } else {
            const_zero[0]
        }
    }));

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

    let initial_state = SHA256_STATE
        .iter()
        .map(|chunk| chunk.to_be_bytes())
        .flatten()
        .into_msb0_iter()
        .map(|bit| if bit { const_one[0] } else { const_zero[0] })
        .collect::<Vec<_>>();

    let hash = padded_msg.chunks(512).fold(initial_state, |state, msg| {
        sha256_compress(&mut builder, &sha256_compress_circ, &msg[..], &state[..])[..].to_vec()
    });

    let mut builder = builder.build_gates();

    let hash_output = builder.add_output("HASH", "32-byte SHA2 hash", ValueType::Bytes, 256);

    builder.connect(&hash[..], &hash_output[..]);

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
