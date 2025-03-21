//! This module contains the protocol for computing TLS SHA-256 HMAC PRF.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod error;
pub(crate) mod hmac;
mod prf;
pub(crate) mod sha256;

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
    use crate::{convert_to_bytes, sha256::sha256};
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::memory::correlated::Delta;
    use rand::{rngs::StdRng, SeedableRng};

    pub(crate) const SHA256_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub(crate) fn mock_vm() -> (Garbler<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Garbler::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    pub(crate) fn prf_reference(key: Vec<u8>, seed: &[u8], iterations: usize) -> Vec<u8> {
        // A() is defined as:
        //
        // A(0) = seed
        // A(i) = HMAC_hash(secret, A(i-1))
        let mut a_cache: Vec<_> = Vec::with_capacity(iterations + 1);
        a_cache.push(seed.to_vec());

        for i in 0..iterations {
            let a_i = hmac_sha256(key.clone(), &a_cache[i]);
            a_cache.push(a_i.to_vec());
        }

        // HMAC_hash(secret, A(i) + seed)
        let mut output: Vec<_> = Vec::with_capacity(iterations * 32);
        for i in 0..iterations {
            let mut a_i_seed = a_cache[i + 1].clone();
            a_i_seed.extend_from_slice(seed);

            let hash = hmac_sha256(key.clone(), &a_i_seed);
            output.extend_from_slice(&hash);
        }

        output
    }

    pub(crate) fn hmac_sha256(key: Vec<u8>, msg: &[u8]) -> [u8; 32] {
        let outer_partial = compute_outer_partial(key.clone());
        let inner_local = compute_inner_local(key, msg);

        let hmac = sha256(outer_partial, 64, &convert_to_bytes(inner_local));
        convert_to_bytes(hmac)
    }

    pub(crate) fn compute_outer_partial(mut key: Vec<u8>) -> [u32; 8] {
        assert!(key.len() <= 64);

        key.resize(64, 0_u8);
        let key_padded: [u8; 64] = key
            .into_iter()
            .map(|b| b ^ 0x5c)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        compress_256(SHA256_IV, &key_padded)
    }

    pub(crate) fn compute_inner_local(mut key: Vec<u8>, msg: &[u8]) -> [u32; 8] {
        assert!(key.len() <= 64);

        key.resize(64, 0_u8);
        let key_padded: [u8; 64] = key
            .into_iter()
            .map(|b| b ^ 0x36)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        let state = compress_256(SHA256_IV, &key_padded);
        sha256(state, 64, msg)
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
}
