use std::sync::Arc;

use crate::hmac_pad;
use mpc_circuits::{builder::CircuitBuilder, circuits::nbyte_xor, BitOrder, Circuit, ValueType};

/// Pre-master Secret
///
/// Parties input their additive shares of the pre-master secret (PMS).
/// Outputs sha256(pms xor opad) called "pms outer hash state" to Notary and
/// also outputs sha256(pms xor ipad) called "pms inner hash state" to User.
///
/// Inputs:
///
///   0. PMS: 32-byte PMS, big endian
///   1. MASK_OUTER: 32-byte mask for outer-state
///   2. MASK_INNER: 32-byte mask for inner-state
///
/// Outputs:
///
///   0. MASKED_OUTER: 32-byte masked HMAC outer hash state
///   1. MASKED_INNER: 32-byte masked HMAC inner hash state
pub fn premaster_secret() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("premaster_secret", "", "0.1.0", BitOrder::Msb0);

    let pms = builder.add_input("PMS", "32-byte PMS, big endian", ValueType::Bytes, 256);
    let mask_outer = builder.add_input(
        "MASK_OUTER",
        "32-byte mask for outer-state",
        ValueType::Bytes,
        256,
    );
    let mask_inner = builder.add_input(
        "MASK_INNER",
        "32-byte mask for inner-state",
        ValueType::Bytes,
        256,
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

    let hmac_outer_pad_circ = hmac_pad(32, [0x5cu8; 64]);
    let hmac_inner_pad_circ = hmac_pad(32, [0x36u8; 64]);
    let xor_256_circ = nbyte_xor(32);

    let hmac_outer_pad = builder.add_circ(&hmac_outer_pad_circ);
    let hmac_inner_pad = builder.add_circ(&hmac_inner_pad_circ);
    let masked_outer_state = builder.add_circ(&xor_256_circ);
    let masked_inner_state = builder.add_circ(&xor_256_circ);

    // outer
    builder.connect(
        &pms[..],
        &hmac_outer_pad.input(0).expect("hmac_pad missing input 0")[..],
    );
    builder.connect(
        &const_zero[..],
        &hmac_outer_pad.input(1).expect("hmac_pad missing input 1")[..],
    );
    builder.connect(
        &const_one[..],
        &hmac_outer_pad.input(2).expect("hmac_pad missing input 2")[..],
    );
    let pms_outer_state = hmac_outer_pad.output(0).expect("hmac_pad missing output 0");

    // inner
    builder.connect(
        &pms[..],
        &hmac_inner_pad.input(0).expect("hmac_pad missing input 0")[..],
    );
    builder.connect(
        &const_zero[..],
        &hmac_inner_pad.input(1).expect("hmac_pad missing input 1")[..],
    );
    builder.connect(
        &const_one[..],
        &hmac_inner_pad.input(2).expect("hmac_pad missing input 2")[..],
    );
    let pms_inner_state = hmac_inner_pad.output(0).expect("hmac_pad missing output 0");

    // mask outer
    builder.connect(
        &pms_outer_state[..],
        &masked_outer_state
            .input(0)
            .expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_outer[..],
        &masked_outer_state
            .input(1)
            .expect("nbit_xor missing input 1")[..],
    );

    // mask inner
    builder.connect(
        &pms_inner_state[..],
        &masked_inner_state
            .input(0)
            .expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_inner[..],
        &masked_inner_state
            .input(1)
            .expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let out_outer = builder.add_output(
        "MASKED_OUTER",
        "32-byte masked HMAC outer hash state",
        ValueType::Bytes,
        256,
    );
    let out_inner = builder.add_output(
        "MASKED_INNER",
        "32-byte masked HMAC inner hash state",
        ValueType::Bytes,
        256,
    );

    builder.connect(
        &masked_outer_state
            .output(0)
            .expect("nbit_xor missing output 0")[..],
        &out_outer[..],
    );

    builder.connect(
        &masked_inner_state
            .output(0)
            .expect("nbit_xor missing output 0")[..],
        &out_inner[..],
    );

    builder
        .build_circuit()
        .expect("failed to build premaster_secret")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{partial_sha256_digest, test_circ};
    use mpc_circuits::Value;
    use num_bigint::{BigUint, RandBigInt};
    use rand::{thread_rng, Rng};

    /// NIST P-256 Prime
    pub const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

    #[test]
    #[ignore = "expensive"]
    fn test_premaster_secret() {
        let circ = premaster_secret();
        // Perform in the clear all the computations which happen inside the ciruit:
        let mut rng = thread_rng();

        let p = BigUint::parse_bytes(P.as_bytes(), 16).unwrap();
        let pms = rng.gen_biguint_below(&p);

        let pms = pms.to_bytes_be();

        // * generate user's and notary's inside-the-GC-masks to mask the GC output
        let mask_n: [u8; 32] = rng.gen();
        let mask_u: [u8; 32] = rng.gen();

        // * XOR pms (zero-padded to 64 bytes) with inner/outer padding of HMAC
        let mut pms_zeropadded = [0u8; 64];
        pms_zeropadded[0..32].copy_from_slice(&pms);

        let pms_opad = pms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let pms_ipad = pms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        // * hash the padded PMS
        let ohash_state = partial_sha256_digest(&pms_opad);
        let ihash_state = partial_sha256_digest(&pms_ipad);
        // convert into u8 array
        let ohash_state_u8: Vec<u8> = ohash_state
            .iter()
            .map(|u32t| u32t.to_be_bytes())
            .flatten()
            .collect();
        let ihash_state_u8: Vec<u8> = ihash_state
            .iter()
            .map(|u32t| u32t.to_be_bytes())
            .flatten()
            .collect();

        // * masked hash state are the expected circuit's outputs
        let expected_outer = ohash_state_u8
            .into_iter()
            .zip(mask_n)
            .map(|(b, mask)| b ^ mask)
            .collect::<Vec<u8>>();
        let expected_inner = ihash_state_u8
            .into_iter()
            .zip(mask_u)
            .map(|(b, mask)| b ^ mask)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(pms),
                Value::Bytes(mask_n.to_vec()),
                Value::Bytes(mask_u.to_vec()),
            ],
            &[Value::Bytes(expected_outer), Value::Bytes(expected_inner)],
        );
    }
}
