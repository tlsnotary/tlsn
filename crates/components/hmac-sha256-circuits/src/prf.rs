//! This module provides an implementation of the HMAC-SHA256 PRF defined in [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246#section-5).

use std::cell::RefCell;

use mpz_circuits::{
    types::{U32, U8},
    BuilderState, Tracer,
};

use crate::hmac_sha256::{hmac_sha256_finalize, hmac_sha256_finalize_trace};

fn p_hash_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    outer_state: [Tracer<'a, U32>; 8],
    inner_state: [Tracer<'a, U32>; 8],
    seed: &[Tracer<'a, U8>],
    iterations: usize,
) -> Vec<Tracer<'a, U8>> {
    // A() is defined as:
    //
    // A(0) = seed
    // A(i) = HMAC_hash(secret, A(i-1))
    let mut a_cache: Vec<_> = Vec::with_capacity(iterations + 1);
    a_cache.push(seed.to_vec());

    for i in 0..iterations {
        let a_i = hmac_sha256_finalize_trace(builder_state, outer_state, inner_state, &a_cache[i]);
        a_cache.push(a_i.to_vec());
    }

    // HMAC_hash(secret, A(i) + seed)
    let mut output: Vec<_> = Vec::with_capacity(iterations * 32);
    for i in 0..iterations {
        let mut a_i_seed = a_cache[i + 1].clone();
        a_i_seed.extend_from_slice(seed);

        let hash = hmac_sha256_finalize_trace(builder_state, outer_state, inner_state, &a_i_seed);
        output.extend_from_slice(&hash);
    }

    output
}

fn p_hash(outer_state: [u32; 8], inner_state: [u32; 8], seed: &[u8], iterations: usize) -> Vec<u8> {
    // A() is defined as:
    //
    // A(0) = seed
    // A(i) = HMAC_hash(secret, A(i-1))
    let mut a_cache: Vec<_> = Vec::with_capacity(iterations + 1);
    a_cache.push(seed.to_vec());

    for i in 0..iterations {
        let a_i = hmac_sha256_finalize(outer_state, inner_state, &a_cache[i]);
        a_cache.push(a_i.to_vec());
    }

    // HMAC_hash(secret, A(i) + seed)
    let mut output: Vec<_> = Vec::with_capacity(iterations * 32);
    for i in 0..iterations {
        let mut a_i_seed = a_cache[i + 1].clone();
        a_i_seed.extend_from_slice(seed);

        let hash = hmac_sha256_finalize(outer_state, inner_state, &a_i_seed);
        output.extend_from_slice(&hash);
    }

    output
}

/// Computes PRF(secret, label, seed).
///
/// # Arguments
///
/// * `builder_state`   - Reference to builder state.
/// * `outer_state`     - The outer state of HMAC-SHA256.
/// * `inner_state`     - The inner state of HMAC-SHA256.
/// * `seed`            - The seed to use.
/// * `label`           - The label to use.
/// * `bytes`           - The number of bytes to output.
pub fn prf_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    outer_state: [Tracer<'a, U32>; 8],
    inner_state: [Tracer<'a, U32>; 8],
    seed: &[Tracer<'a, U8>],
    label: &[Tracer<'a, U8>],
    bytes: usize,
) -> Vec<Tracer<'a, U8>> {
    let iterations = bytes / 32 + (bytes % 32 != 0) as usize;
    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);

    let mut output = p_hash_trace(
        builder_state,
        outer_state,
        inner_state,
        &label_seed,
        iterations,
    );
    output.truncate(bytes);

    output
}

/// Reference implementation of PRF(secret, label, seed).
///
/// # Arguments
///
/// * `outer_state` - The outer state of HMAC-SHA256.
/// * `inner_state` - The inner state of HMAC-SHA256.
/// * `seed`        - The seed to use.
/// * `label`       - The label to use.
/// * `bytes`       - The number of bytes to output.
pub fn prf(
    outer_state: [u32; 8],
    inner_state: [u32; 8],
    seed: &[u8],
    label: &[u8],
    bytes: usize,
) -> Vec<u8> {
    let iterations = bytes / 32 + (bytes % 32 != 0) as usize;
    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);

    let mut output = p_hash(outer_state, inner_state, &label_seed, iterations);
    output.truncate(bytes);

    output
}

#[cfg(test)]
mod tests {
    use mpz_circuits::{evaluate, CircuitBuilder};

    use crate::hmac_sha256::hmac_sha256_partial;

    use super::*;

    #[test]
    fn test_p_hash() {
        let builder = CircuitBuilder::new();
        let outer_state = builder.add_array_input::<u32, 8>();
        let inner_state = builder.add_array_input::<u32, 8>();
        let seed = builder.add_array_input::<u8, 64>();
        let output = p_hash_trace(builder.state(), outer_state, inner_state, &seed, 2);
        builder.add_output(output);
        let circ = builder.build().unwrap();

        let outer_state = [0u32; 8];
        let inner_state = [1u32; 8];
        let seed = [42u8; 64];

        let expected = p_hash(outer_state, inner_state, &seed, 2);
        let actual = evaluate!(circ, fn(outer_state, inner_state, &seed) -> Vec<u8>).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_prf() {
        let builder = CircuitBuilder::new();
        let outer_state = builder.add_array_input::<u32, 8>();
        let inner_state = builder.add_array_input::<u32, 8>();
        let seed = builder.add_array_input::<u8, 64>();
        let label = builder.add_array_input::<u8, 13>();
        let output = prf_trace(builder.state(), outer_state, inner_state, &seed, &label, 48);
        builder.add_output(output);
        let circ = builder.build().unwrap();

        let master_secret = [0u8; 48];
        let seed = [43u8; 64];
        let label = b"master secret";

        let (outer_state, inner_state) = hmac_sha256_partial(&master_secret);

        let expected = prf(outer_state, inner_state, &seed, label, 48);
        let actual =
            evaluate!(circ, fn(outer_state, inner_state, &seed, label) -> Vec<u8>).unwrap();

        assert_eq!(actual, expected);

        let mut expected_ring = [0u8; 48];
        ring_prf::prf(&mut expected_ring, &master_secret, label, &seed);

        assert_eq!(actual, expected_ring);
    }

    // Borrowed from Rustls for testing
    // https://github.com/rustls/rustls/blob/main/rustls/src/tls12/prf.rs
    mod ring_prf {
        use ring::{hmac, hmac::HMAC_SHA256};

        fn concat_sign(key: &hmac::Key, a: &[u8], b: &[u8]) -> hmac::Tag {
            let mut ctx = hmac::Context::with_key(key);
            ctx.update(a);
            ctx.update(b);
            ctx.sign()
        }

        fn p(out: &mut [u8], secret: &[u8], seed: &[u8]) {
            let hmac_key = hmac::Key::new(HMAC_SHA256, secret);

            // A(1)
            let mut current_a = hmac::sign(&hmac_key, seed);
            let chunk_size = HMAC_SHA256.digest_algorithm().output_len();
            for chunk in out.chunks_mut(chunk_size) {
                // P_hash[i] = HMAC_hash(secret, A(i) + seed)
                let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
                chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

                // A(i+1) = HMAC_hash(secret, A(i))
                current_a = hmac::sign(&hmac_key, current_a.as_ref());
            }
        }

        fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
            let mut ret = Vec::new();
            ret.extend_from_slice(a);
            ret.extend_from_slice(b);
            ret
        }

        pub(crate) fn prf(out: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
            let joined_seed = concat(label, seed);
            p(out, secret, &joined_seed);
        }
    }
}
