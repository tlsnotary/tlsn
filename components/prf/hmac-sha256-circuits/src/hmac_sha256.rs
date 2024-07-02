use std::cell::RefCell;

use mpz_circuits::{
    circuits::{sha256, sha256_compress, sha256_compress_trace, sha256_trace},
    types::{U32, U8},
    BuilderState, Tracer,
};

static SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Returns the outer and inner states of HMAC-SHA256 with the provided key.
///
/// Outer state is H(key ⊕ opad)
///
/// Inner state is H(key ⊕ ipad)
///
/// # Arguments
///
/// * `builder_state`   - Reference to builder state.
/// * `key`             - N-byte key (must be <= 64 bytes).
pub fn hmac_sha256_partial_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    key: &[Tracer<'a, U8>],
) -> ([Tracer<'a, U32>; 8], [Tracer<'a, U32>; 8]) {
    assert!(key.len() <= 64);

    let mut opad = [Tracer::new(
        builder_state,
        builder_state.borrow_mut().get_constant(0x5cu8),
    ); 64];

    let mut ipad = [Tracer::new(
        builder_state,
        builder_state.borrow_mut().get_constant(0x36u8),
    ); 64];

    key.iter().enumerate().for_each(|(i, k)| {
        opad[i] = opad[i] ^ *k;
        ipad[i] = ipad[i] ^ *k;
    });

    let sha256_initial_state: [_; 8] = SHA256_INITIAL_STATE
        .map(|v| Tracer::new(builder_state, builder_state.borrow_mut().get_constant(v)));

    let outer_state = sha256_compress_trace(builder_state, sha256_initial_state, opad);
    let inner_state = sha256_compress_trace(builder_state, sha256_initial_state, ipad);

    (outer_state, inner_state)
}

/// Reference implementation of HMAC-SHA256 partial function.
///
/// Returns the outer and inner states of HMAC-SHA256 with the provided key.
///
/// Outer state is H(key ⊕ opad)
///
/// Inner state is H(key ⊕ ipad)
///
/// # Arguments
///
/// * `key` - N-byte key (must be <= 64 bytes).
pub fn hmac_sha256_partial(key: &[u8]) -> ([u32; 8], [u32; 8]) {
    assert!(key.len() <= 64);

    let mut opad = [0x5cu8; 64];
    let mut ipad = [0x36u8; 64];

    key.iter().enumerate().for_each(|(i, k)| {
        opad[i] ^= k;
        ipad[i] ^= k;
    });

    let outer_state = sha256_compress(SHA256_INITIAL_STATE, opad);
    let inner_state = sha256_compress(SHA256_INITIAL_STATE, ipad);

    (outer_state, inner_state)
}

/// HMAC-SHA256 finalization function.
///
/// Returns the HMAC-SHA256 digest of the provided message using existing outer and inner states.
///
/// # Arguments
///
/// * `outer_state` - 256-bit outer state.
/// * `inner_state` - 256-bit inner state.
/// * `msg`         - N-byte message.
pub fn hmac_sha256_finalize_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    outer_state: [Tracer<'a, U32>; 8],
    inner_state: [Tracer<'a, U32>; 8],
    msg: &[Tracer<'a, U8>],
) -> [Tracer<'a, U8>; 32] {
    sha256_trace(
        builder_state,
        outer_state,
        64,
        &sha256_trace(builder_state, inner_state, 64, msg),
    )
}

/// Reference implementation of the HMAC-SHA256 finalization function.
///
/// Returns the HMAC-SHA256 digest of the provided message using existing outer and inner states.
///
/// # Arguments
///
/// * `outer_state` - 256-bit outer state.
/// * `inner_state` - 256-bit inner state.
/// * `msg`         - N-byte message.
pub fn hmac_sha256_finalize(outer_state: [u32; 8], inner_state: [u32; 8], msg: &[u8]) -> [u8; 32] {
    sha256(outer_state, 64, &sha256(inner_state, 64, msg))
}

#[cfg(test)]
mod tests {
    use mpz_circuits::{test_circ, CircuitBuilder};

    use super::*;

    #[test]
    fn test_hmac_sha256_partial() {
        let builder = CircuitBuilder::new();
        let key = builder.add_array_input::<u8, 48>();
        let (outer_state, inner_state) = hmac_sha256_partial_trace(builder.state(), &key);
        builder.add_output(outer_state);
        builder.add_output(inner_state);
        let circ = builder.build().unwrap();

        let key = [69u8; 48];

        test_circ!(circ, hmac_sha256_partial, fn(&key) -> ([u32; 8], [u32; 8]));
    }

    #[test]
    fn test_hmac_sha256_finalize() {
        let builder = CircuitBuilder::new();
        let outer_state = builder.add_array_input::<u32, 8>();
        let inner_state = builder.add_array_input::<u32, 8>();
        let msg = builder.add_array_input::<u8, 47>();
        let hash = hmac_sha256_finalize_trace(builder.state(), outer_state, inner_state, &msg);
        builder.add_output(hash);
        let circ = builder.build().unwrap();

        let key = [69u8; 32];
        let (outer_state, inner_state) = hmac_sha256_partial(&key);
        let msg = [42u8; 47];

        test_circ!(
            circ,
            hmac_sha256_finalize,
            fn(outer_state, inner_state, &msg) -> [u8; 32]
        );
    }
}
