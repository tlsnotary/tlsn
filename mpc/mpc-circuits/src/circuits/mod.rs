//! Pre-built circuits for MPC.

pub mod big_num;

use once_cell::sync::Lazy;
use std::{cell::RefCell, sync::Arc};

use crate::{
    types::{BinaryRepr, U32, U8},
    BuilderState, Circuit, CircuitBuilder, Tracer,
};

/// AES-128 circuit.
///
/// The circuit has the following signature:
///
/// `fn(key: [u8; 16], msg: [u8; 16]) -> [u8; 16]`
#[cfg(feature = "aes")]
pub static AES128: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../../circuits/bin/aes_128.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// SHA-256 circuit.
///
/// The circuit has the following signature:
///
/// `fn(state: [u32; 8], msg: [u8; 64]) -> [u32; 8]`
#[cfg(feature = "sha2")]
pub static SHA256_COMPRESS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../../circuits/bin/sha256.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// AES-128 circuit trace.
///
/// This function is a wrapper around the AES-128 circuit that can be used to append
/// it to other circuits.
///
/// # Arguments
///
/// * `state` - The builder state to append the circuit to.
/// * `key` - The key to use.
/// * `msg` - The message to encrypt.
///
/// # Returns
///
/// The ciphertext.
#[cfg(feature = "aes")]
pub fn aes128_trace<'a>(
    state: &'a RefCell<BuilderState>,
    key: [Tracer<'a, U8>; 16],
    msg: [Tracer<'a, U8>; 16],
) -> [Tracer<'a, U8>; 16] {
    let mut outputs = state
        .borrow_mut()
        .append(&AES128, &[key.into(), msg.into()])
        .expect("aes 128 should append successfully");

    let BinaryRepr::Array(ciphertext) = outputs.pop().unwrap() else {
        panic!("aes 128 should have array output");
    };

    let ciphertext: [_; 16] = ciphertext.try_into().unwrap();

    ciphertext.map(|value| Tracer::new(state, value.try_into().unwrap()))
}

/// SHA-256 compression circuit trace.
///
/// This function is a wrapper around the SHA256 compression circuit that can be used to append
/// it to other circuits.
///
/// # Arguments
///
/// * `builder_state` - The builder state to append the circuit to.
/// * `state` - The SHA256 state.
/// * `msg` - The message to compress.
///
/// # Returns
///
/// The SHA256 state after compression.
#[cfg(feature = "sha2")]
pub fn sha256_compress_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    state: [Tracer<'a, U32>; 8],
    msg: [Tracer<'a, U8>; 64],
) -> [Tracer<'a, U32>; 8] {
    let mut outputs = builder_state
        .borrow_mut()
        .append(&SHA256_COMPRESS, &[state.into(), msg.into()])
        .expect("sha 256 should append successfully");

    let BinaryRepr::Array(output) = outputs.pop().unwrap() else {
        panic!("sha 256 should have array output");
    };

    let output: [_; 8] = output.try_into().unwrap();

    output.map(|value| Tracer::new(builder_state, value.try_into().unwrap()))
}

/// Builds a circuit to compute the SHA-256 hash of a message.
///
/// # Arguments
///
/// * `pos` - The number of bytes in the message that have already been hashed.
/// * `msg_len` - The total length of the hashed message.
///
/// # Returns a circuit with the following signature:
///
/// `fn(state: [u32; 8], msg: [u8; msg_len]) -> [u8; 32]`
#[cfg(feature = "sha2")]
pub fn build_sha256(pos: usize, msg_len: usize) -> Circuit {
    let builder = CircuitBuilder::new();
    let mut state = builder.add_array_input::<u32, 8>();
    let mut msg = builder.add_vec_input::<u8>(msg_len);

    let bit_len = msg_len * 8;
    let processed_bit_len = (bit_len + (pos * 8)) as u64;

    // minimum length of padded message in bytes
    let min_padded_len = msg_len + 9;
    // number of 64-byte blocks rounded up
    let block_count = (min_padded_len / 64) + (min_padded_len % 64 != 0) as usize;
    // message is padded to a multiple of 64 bytes
    let padded_len = block_count * 64;
    // number of bytes to pad
    let pad_len = padded_len - msg_len;

    // append a single '1' bit
    // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    // such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> , (the number of bits will be a multiple of 512)
    msg.push(builder.get_constant(128u8));
    msg.extend((0..pad_len - 9).map(|_| builder.get_constant(0u8)));
    msg.extend(
        processed_bit_len
            .to_be_bytes()
            .iter()
            .map(|&value| builder.get_constant(value)),
    );

    debug_assert!(msg.len() % 64 == 0);

    for block in msg.chunks(64) {
        state = sha256_compress_trace(
            builder.state(),
            state,
            block.try_into().expect("block is 64 bytes"),
        );
    }

    let hash = state
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect::<Vec<_>>();
    let hash: [_; 32] = hash.try_into().expect("hash is 32 bytes");

    builder.add_output(hash);

    builder.build().expect("circuit is valid")
}

/// SHA-256 circuit trace.
///
/// This function is a wrapper around the SHA256 circuit that can be used
/// to compute the hash of an arbitrary length message.
///
/// # Arguments
///
/// * `builder_state` - The builder state to append the circuit to.
/// * `state` - The SHA256 state.
/// * `pos` - The number of bytes processed in the current state.
/// * `msg` - The message to hash.
#[cfg(feature = "sha2")]
pub fn sha256_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    state: [Tracer<'a, U32>; 8],
    pos: usize,
    msg: &[Tracer<'a, U8>],
) -> [Tracer<'a, U8>; 32] {
    let circ = build_sha256(pos, msg.len());
    let mut outputs = builder_state
        .borrow_mut()
        .append(&circ, &[state.into(), msg.to_vec().into()])
        .expect("circuit should append successfully");

    let BinaryRepr::Array(hash) = outputs.pop().unwrap() else {
        panic!("circuit should have array output");
    };

    let hash: [_; 32] = hash.try_into().expect("hash should be 32 bytes");

    hash.map(|value| Tracer::new(builder_state, value.try_into().unwrap()))
}

/// Reference SHA256 compression function implementation.
///
/// # Arguments
///
/// * `state` - The SHA256 state.
/// * `msg` - The message to compress.
#[cfg(feature = "sha2")]
pub fn sha256_compress(state: [u32; 8], msg: [u8; 64]) -> [u32; 8] {
    let mut state = state;
    sha2::compress256(&mut state, &[msg.into()]);
    state
}

/// Reference SHA256 implementation.
///
/// # Arguments
///
/// * `state` - The SHA256 state.
/// * `pos` - The number of bytes processed in the current state.
/// * `msg` - The message to hash.
#[cfg(feature = "sha2")]
pub fn sha256(mut state: [u32; 8], pos: usize, msg: &[u8]) -> [u8; 32] {
    use sha2::{
        compress256,
        digest::{
            block_buffer::{BlockBuffer, Eager},
            generic_array::typenum::U64,
        },
    };

    let mut buffer = BlockBuffer::<U64, Eager>::default();
    buffer.digest_blocks(msg, |b| compress256(&mut state, b));
    buffer.digest_pad(0x80, &(((msg.len() + pos) * 8) as u64).to_be_bytes(), |b| {
        compress256(&mut state, &[*b])
    });

    let mut out: [u8; 32] = [0; 32];
    for (chunk, v) in out.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpc_circuits_macros::test_circ;

    static SHA2_INITIAL_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[test]
    #[cfg(feature = "aes")]
    fn test_aes128() {
        fn aes_128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
            use aes::{Aes128, BlockEncrypt, NewBlockCipher};

            let aes = Aes128::new_from_slice(&key).unwrap();
            let mut ciphertext = msg.into();
            aes.encrypt_block(&mut ciphertext);
            ciphertext.into()
        }

        test_circ!(
            AES128,
            aes_128,
            fn([0u8; 16], [69u8; 16]) -> [u8; 16]
        );
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_sha256_compress() {
        test_circ!(
            SHA256_COMPRESS,
            sha256_compress,
            fn(SHA2_INITIAL_STATE, [69u8; 64]) -> [u32; 8]
        );
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_sha256() {
        for len in [5, 64, 100] {
            let msg = vec![0u8; len];
            let circ = build_sha256(0, len);
            let reference = |state, msg| sha256(state, 0, msg);

            test_circ!(circ, reference, fn(SHA2_INITIAL_STATE, msg.as_slice()) -> [u8; 32]);
        }
    }
}
