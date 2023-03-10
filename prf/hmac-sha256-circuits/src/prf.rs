//! This module provides an implementation of the HMAC-SHA256 PRF defined in [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246#section-5).

use std::sync::Arc;

use mpc_circuits::{
    builder::{CircuitBuilder, Feed, Gates, WireHandle},
    BitOrder, Circuit, ValueType,
};

use utils::bits::IterToBits;

use crate::{add_hmac_sha256_finalize, add_hmac_sha256_partial};

// P_hash(secret, seed) =
//   HMAC_hash(secret, A(1) + seed) +
//   HMAC_hash(secret, A(2) + seed) +
//   HMAC_hash(secret, A(3) + seed) + ...
fn add_p_hash(
    builder: &mut CircuitBuilder<Gates>,
    outer_state: &[WireHandle<Feed>],
    inner_state: &[WireHandle<Feed>],
    const_zero: &WireHandle<Feed>,
    const_one: &WireHandle<Feed>,
    seed: &[WireHandle<Feed>],
    iterations: usize,
) -> Vec<WireHandle<Feed>> {
    // A() is defined as:
    //
    // A(0) = seed
    // A(i) = HMAC_hash(secret, A(i-1))
    let mut a_cache: Vec<_> = Vec::with_capacity(iterations + 1);
    a_cache.push(seed.to_vec());

    for i in 0..iterations {
        let a_i = add_hmac_sha256_finalize(
            builder,
            outer_state,
            inner_state,
            &a_cache[i],
            const_zero,
            const_one,
        );
        a_cache.push(a_i);
    }

    // HMAC_hash(secret, A(i) + seed)
    let mut output: Vec<WireHandle<Feed>> = Vec::with_capacity(iterations * 32 * 8);
    for i in 0..iterations {
        let mut a_i_seed = a_cache[i + 1].clone();
        a_i_seed.extend_from_slice(seed);

        let hash = add_hmac_sha256_finalize(
            builder,
            outer_state,
            inner_state,
            &a_i_seed,
            const_zero,
            const_one,
        );
        output.extend_from_slice(&hash);
    }

    output
}

/// Computes PRF(secret, label, seed)
///
/// # Arguments
///
/// * `builder` - Mutable reference to the circuit builder
/// * `outer_state` - The outer state of HMAC-SHA256
/// * `inner_state` - The inner state of HMAC-SHA256
/// * `const_zero` - A constant wire that is always 0
/// * `const_one` - A constant wire that is always 1
/// * `label` - The label to use
/// * `seed` - The seed to use
/// * `bytes` - The number of bytes to output
///
/// # Returns
///
/// * `prf_bytes` - `bytes` bytes of output
pub fn add_prf(
    builder: &mut CircuitBuilder<Gates>,
    outer_state: &[WireHandle<Feed>],
    inner_state: &[WireHandle<Feed>],
    const_zero: &WireHandle<Feed>,
    const_one: &WireHandle<Feed>,
    label: &[WireHandle<Feed>],
    seed: &[WireHandle<Feed>],
    bytes: usize,
) -> Vec<WireHandle<Feed>> {
    let iterations = bytes / 32 + (bytes % 32 != 0) as usize;

    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);

    let p_hash = add_p_hash(
        builder,
        outer_state,
        inner_state,
        const_zero,
        const_one,
        &label_seed,
        iterations,
    );

    // Truncate to the desired number of bytes
    let prf_bytes = p_hash[..bytes * 8].to_vec();

    prf_bytes
}

/// Computes PRF(key, seed)
///
/// Inputs:
///
///   0. KEY: 32-byte key
///   1. SEED: N-byte seed
///
/// Outputs:
///
///   0. BYTES: N-byte output
///
/// # Arguments
/// * `name` - The name of the circuit
/// * `description` - The description of the circuit
/// * `label` - The label to use
/// * `key_len` - The length of the key in bytes
/// * `seed_len` - The length of the seed in bytes
/// * `output_len` - The number of bytes to generate
pub fn prf(
    name: &str,
    description: &str,
    label: &[u8],
    key_len: usize,
    seed_len: usize,
    output_len: usize,
) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(name, description, "0.1.0", BitOrder::Msb0);

    let key = builder.add_input(
        "KEY",
        &format!("{key_len}-byte key"),
        ValueType::Bytes,
        key_len * 8,
    );
    let seed = builder.add_input(
        "SEED",
        &format!("{seed_len}-byte seed"),
        ValueType::Bytes,
        seed_len * 8,
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

    let label = label
        .into_iter()
        .copied()
        .into_msb0_iter()
        .map(|bit| if bit { const_one[0] } else { const_zero[0] })
        .collect::<Vec<_>>();

    let (outer_state, inner_state) =
        add_hmac_sha256_partial(&mut builder, &key[..], &const_zero[0], &const_one[0]);

    let prf_bytes = add_prf(
        &mut builder,
        &outer_state,
        &inner_state,
        &const_zero[0],
        &const_one[0],
        &label,
        &seed[..],
        output_len,
    );

    let mut builder = builder.build_gates();

    let bytes_out = builder.add_output(
        "BYTES",
        &format!("{output_len}-byte output"),
        ValueType::Bytes,
        output_len * 8,
    );

    builder.connect(&prf_bytes, &bytes_out[..]);

    builder.build_circuit().expect("failed to build prf")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{self, test_circ};
    use mpc_circuits::Value;

    #[test]
    #[ignore = "expensive"]
    fn test_prf() {
        let pms = [69u8; 32];
        let label = b"master secret";
        let client_random = [42u8; 32];
        let server_random = [69u8; 32];

        let seed = {
            let mut seed = Vec::new();
            seed.extend_from_slice(&client_random);
            seed.extend_from_slice(&server_random);
            seed
        };

        let circ = prf("ms", "", label, 32, 64, 48);

        let expected = test_helpers::prf(&pms, label, &seed, 48);

        test_circ(
            &circ,
            &[Value::Bytes(pms.to_vec()), Value::Bytes(seed)],
            &[Value::Bytes(expected)],
        );
    }
}
