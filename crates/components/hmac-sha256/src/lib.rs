//! This module contains the protocol for computing TLS SHA-256 HMAC PRF.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod error;
pub(crate) mod hmac;
mod prf;
pub(crate) mod sha256;
#[cfg(test)]
pub(crate) mod test_utils;

pub use error::PrfError;
pub use prf::MpcPrf;

use mpz_vm_core::memory::{binary::U8, Array};

/// PRF output.
#[derive(Debug, Clone, Copy)]
pub struct PrfOutput {
    /// TLS session keys.
    pub keys: SessionKeys,
    /// Client finished verify data.
    pub cf_vd: Array<U8, 12>,
    /// Server finished verify data.
    pub sf_vd: Array<U8, 12>,
}

/// Session keys computed by the PRF.
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Client IV.
    pub client_iv: Array<U8, 4>,
    /// Server IV.
    pub server_iv: Array<U8, 4>,
}

fn convert_to_bytes(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (k, byte_chunk) in input.iter().enumerate() {
        let byte_chunk = byte_chunk.to_be_bytes();
        output[4 * k..4 * (k + 1)].copy_from_slice(&byte_chunk);
    }
    output
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_prf() {
        todo!()
    }
}
