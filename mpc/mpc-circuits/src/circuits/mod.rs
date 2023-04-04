//! Pre-built circuits for MPC.

pub mod big_num;

use once_cell::sync::Lazy;
use std::{cell::RefCell, sync::Arc};

use crate::{
    types::{BinaryRepr, U32, U8},
    BuilderState, Circuit, Tracer,
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
pub static SHA256: Lazy<Arc<Circuit>> = Lazy::new(|| {
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

/// SHA-256 circuit trace.
///
/// This function is a wrapper around the SHA256 circuit that can be used to append
/// it to other circuits.
///
/// # Arguments
///
/// * `builder_state` - The builder state to append the circuit to.
/// * `state` - The initial SHA256 state.
/// * `msg` - The message to compress.
///
/// # Returns
///
/// The SHA256 state after compression.
pub fn sha256_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    state: [Tracer<'a, U32>; 8],
    msg: [Tracer<'a, U8>; 64],
) -> [Tracer<'a, U32>; 8] {
    let mut outputs = builder_state
        .borrow_mut()
        .append(&SHA256, &[state.into(), msg.into()])
        .expect("sha 256 should append successfully");

    let BinaryRepr::Array(output) = outputs.pop().unwrap() else {
        panic!("sha 256 should have array output");
    };

    let output: [_; 8] = output.try_into().unwrap();

    output.map(|value| Tracer::new(builder_state, value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::evaluate;

    #[test]
    #[cfg(feature = "aes")]
    fn test_aes128() {
        use aes::{Aes128, BlockEncrypt, NewBlockCipher};

        let key = [0u8; 16];
        let msg = [69u8; 16];

        let ciphertext = evaluate!(AES128, fn(key, msg) -> [u8; 16]).unwrap();

        let aes = Aes128::new_from_slice(&key).unwrap();
        let mut expected = msg.into();
        aes.encrypt_block(&mut expected);
        let expected: [u8; 16] = expected.into();

        assert_eq!(ciphertext, expected);
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_sha256() {
        use sha2::compress256;

        static SHA2_INITIAL_STATE: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let msg = [69u8; 64];

        let output = evaluate!(SHA256, fn(SHA2_INITIAL_STATE, msg) -> [u32; 8]).unwrap();

        let mut expected = SHA2_INITIAL_STATE;
        compress256(&mut expected, &[msg.into()]);

        assert_eq!(output, expected);
    }
}
