use std::sync::Arc;

use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder, Feed, Gates, SubOutputHandle, WireHandle},
    circuits::nbit_xor,
    BitOrder, Circuit, ValueType,
};

use crate::{hmac_pad, hmac_sha256_finalize, sha256};

fn A(
    builder: &mut CircuitBuilder<Gates>,
    hmac_finalize_seed: &Circuit,
    hmac_finalize: &Circuit,
    inner_state: &[WireHandle<Feed>],
    outer_state: &[WireHandle<Feed>],
    const_zero: &[WireHandle<Feed>],
    const_one: &[WireHandle<Feed>],
    seed: &[WireHandle<Feed>],
    n: usize,
) -> SubOutputHandle {
    let (a, msg) = if n == 1 {
        (builder.add_circ(hmac_finalize_seed), seed.to_vec())
    } else {
        let a = builder.add_circ(hmac_finalize);

        let a_prev = A(
            builder,
            hmac_finalize_seed,
            hmac_finalize,
            inner_state,
            outer_state,
            const_zero,
            const_one,
            seed,
            n,
        );

        (a, a_prev[..].to_vec())
    };

    let input_inner_state = a
        .input(0)
        .expect("hmac_sha256_finalize should have input 0");
    let input_outer_state = a
        .input(1)
        .expect("hamc_sha256_finalize should have input 1");
    let input_msg = a
        .input(2)
        .expect("hmac_sha256_finalize should have input 2");

    builder.connect(inner_state, &input_inner_state[..]);
    builder.connect(outer_state, &input_outer_state[..]);
    builder.connect(
        const_zero,
        &a.input(3)
            .expect("hmac_sha256_finalize should have input 3")[..],
    );
    builder.connect(
        const_one,
        &a.input(4)
            .expect("hmac_sha256_finalize should have input 4")[..],
    );

    builder.connect(&msg, &input_msg[..]);

    a.output(0)
        .expect("hmac_sha256_finalize should have output 0")
}

/// Computes PRF(k, seed)
///
/// Inputs:
///
///   0. KEY: 32-byte key
///   1. SEED: N-byte seed
///
/// Outputs:
///
///   0. HASH: 32-byte hash
///
/// # Arguments
/// * `seed_len` - The length of the seed in bytes
/// * `iterations` - The number of iterations to perform (32 bytes per iteration)
pub fn prf(seed_len: usize, iterations: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(
        &format!("prf_{seed_len}_{iterations}"),
        "",
        "0.1.0",
        BitOrder::Msb0,
    );

    let key = builder.add_input("KEY", "32-byte key", ValueType::Bytes, 256);
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

    let hmac_finalize_seed = hmac_sha256_finalize(seed_len);
    let hmac_finalize = hmac_sha256_finalize(32 + seed_len);

    let inner_hash_state_circ = builder.add_circ(&hmac_pad(32, [0x36; 64]));
    let outer_hash_state_circ = builder.add_circ(&hmac_pad(32, [0x5c; 64]));

    let inner_hash_state = {
        // Connect key wires
        builder.connect(
            &key[..],
            &inner_hash_state_circ
                .input(0)
                .expect("hmac_pad should have input 0")[..],
        );
        // Connect constant wires
        builder.connect(
            &const_zero[..],
            &inner_hash_state_circ
                .input(1)
                .expect("hmac_pad should have input 1")[..],
        );
        builder.connect(
            &const_one[..],
            &inner_hash_state_circ
                .input(2)
                .expect("hmac_pad should have input 2")[..],
        );

        inner_hash_state_circ
            .output(0)
            .expect("hmac_pad should have output 0")
    };

    let outer_hash_state = {
        // Connect key wires
        builder.connect(
            &key[..],
            &outer_hash_state_circ
                .input(0)
                .expect("hmac_pad should have input 0")[..],
        );
        // Connect constant wires
        builder.connect(
            &const_zero[..],
            &outer_hash_state_circ
                .input(1)
                .expect("hmac_pad should have input 1")[..],
        );
        builder.connect(
            &const_one[..],
            &outer_hash_state_circ
                .input(2)
                .expect("hmac_pad should have input 2")[..],
        );

        outer_hash_state_circ
            .output(0)
            .expect("hmac_pad should have output 0")
    };

    let output_hash = A(
        &mut builder,
        &hmac_finalize_seed,
        &hmac_finalize,
        &inner_hash_state[..],
        &outer_hash_state[..],
        &const_zero[..],
        &const_one[..],
        &seed[..],
        1,
    );

    let mut builder = builder.build_gates();

    let hash = builder.add_output("HASH", "32-byte hash", ValueType::Bytes, 256);

    builder.connect(&output_hash[..], &hash[..]);

    builder
        .build_circuit()
        .expect("failed to build hmac_sha256")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{partial_sha256_digest, test_circ};
    use mpc_circuits::Value;

    use hmac::{Hmac, Mac};

    #[test]
    #[ignore = "expensive"]
    fn test_hmac_sha256() {
        let key = [69u8; 32];
        let label = b"master secret";
        let client_random = [42u8; 32];
        let server_random = [69u8; 32];

        let mut seed = [0u8; 77];
        seed[..13].copy_from_slice(label);
        seed[13..45].copy_from_slice(&client_random);
        seed[45..].copy_from_slice(&server_random);

        let circ = prf(77, 2);

        // let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
        // hmac.update(&msg);
        // let expected = hmac.finalize().into_bytes().to_vec();

        test_circ(
            &circ,
            &[Value::Bytes(key.to_vec()), Value::Bytes(seed.to_vec())],
            &[Value::Bytes(vec![])],
        );
    }
}
