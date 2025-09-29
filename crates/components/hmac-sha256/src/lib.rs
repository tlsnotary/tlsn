//! MPC protocols for computing HMAC-SHA-256-based PRF for TLS 1.2 and key
//! schedule for TLS 1.3.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod hmac;
#[cfg(test)]
mod test_utils;

mod config;
pub use config::Mode;

mod error;
pub use error::FError;

mod kdf;
mod prf;
mod tls12;
mod tls13;

pub use tls12::{PrfOutput, SessionKeys, Tls12Prf};
pub use tls13::{ApplicationKeys, HandshakeKeys, Role, Tls13KeySched};

fn sha256(mut state: [u32; 8], pos: usize, msg: &[u8]) -> [u32; 8] {
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
    state
}

pub(crate) fn compress_256(mut state: [u32; 8], msg: &[u8]) -> [u32; 8] {
    use sha2::{
        compress256,
        digest::{
            block_buffer::{BlockBuffer, Eager},
            generic_array::typenum::U64,
        },
    };

    let mut buffer = BlockBuffer::<U64, Eager>::default();
    buffer.digest_blocks(msg, |b| compress256(&mut state, b));
    state
}

fn state_to_bytes(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (k, byte_chunk) in input.iter().enumerate() {
        let byte_chunk = byte_chunk.to_be_bytes();
        output[4 * k..4 * (k + 1)].copy_from_slice(&byte_chunk);
    }
    output
}
