use std::sync::Arc;

use crate::{combine_pms_shares, SHA256_STATE};
use mpc_circuits::{
    builder::{map_le_bytes, CircuitBuilder},
    circuits::nbit_xor,
    Circuit, ValueType, SHA_256,
};

/// TLS stage 1
///
/// Parties input their additive shares of the pre-master secret (PMS).
/// Outputs sha256(pms xor opad) called "pms outer hash state" to Notary and
/// also outputs sha256(pms xor ipad) called "pms inner hash state" to User.
///
/// Inputs:
///
///   0. PMS_SHARE_A: 32-byte PMS Additive Share
///   1. PMS_SHARE_B: 32-byte PMS Additive Share
///   2. MASK_I: 32-byte mask for inner-state
///   3. MASK_O: 32-byte mask for outer-state
///
/// Outputs:
///
///   0. MASKED_I: 32-byte masked HMAC inner hash state
///   1. MASKED_O: 32-byte masked HMAC outer hash state
pub fn c1() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("c1", "", "0.1.0");

    let share_a = builder.add_input(
        "PMS_SHARE_A",
        "32-byte PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let share_b = builder.add_input(
        "PMS_SHARE_B",
        "32-byte PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let mask_inner = builder.add_input(
        "MASK_I",
        "32-byte mask for inner-state",
        ValueType::Bytes,
        256,
    );
    let mask_outer = builder.add_input(
        "MASK_O",
        "32-byte mask for outer-state",
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

    let sha256 = Circuit::load_bytes(SHA_256).expect("failed to load sha256 circuit");
    let xor_512_circ = nbit_xor(512);
    let xor_256_circ = nbit_xor(256);

    let combine_pms = builder.add_circ(&combine_pms_shares());
    let sha256_ipad = builder.add_circ(&sha256);
    let sha256_opad = builder.add_circ(&sha256);
    let pms_ipad = builder.add_circ(&xor_512_circ);
    let pms_opad = builder.add_circ(&xor_512_circ);
    let masked_inner = builder.add_circ(&xor_256_circ);
    let masked_outer = builder.add_circ(&xor_256_circ);

    builder.connect(
        &share_a[..],
        &combine_pms
            .input(0)
            .expect("combine_pms_shares missing input 0")[..],
    );
    builder.connect(
        &share_b[..],
        &combine_pms
            .input(1)
            .expect("combine_pms_shares missing input 0")[..],
    );
    builder.connect(
        &const_zero[..],
        &combine_pms
            .input(2)
            .expect("combine_pms_shares missing input 2")[..],
    );
    builder.connect(
        &const_one[..],
        &combine_pms
            .input(3)
            .expect("combine_pms_shares missing input 3")[..],
    );

    let pms = combine_pms
        .output(0)
        .expect("combine_pms_shares missing output 0");

    // inner
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &pms_ipad.input(0).expect("nbit_xor missing input 0")[..],
        &[0x36u8; 64],
    );
    builder.connect(
        &pms[..],
        &pms_ipad.input(1).expect("nbit_xor missing input 1")[256..],
    );
    builder.connect(
        &[const_zero[0]; 256],
        &pms_ipad.input(1).expect("nbit_xor missing input 1")[..256],
    );
    builder.connect(
        &pms_ipad.output(0).expect("nbit_xor missing output 0")[..],
        &sha256_ipad.input(0).expect("sha256 missing input 0")[..],
    );
    // map SHA256 initial state
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &sha256_ipad.input(1).expect("sha256 missing input 1")[..],
        &SHA256_STATE
            .iter()
            .rev()
            .map(|chunk| chunk.to_le_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    );

    // outer
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &pms_opad.input(0).expect("nbit_xor missing input 0")[..],
        &[0x5cu8; 64],
    );
    builder.connect(
        &pms[..],
        &pms_opad.input(1).expect("nbit_xor missing input 1")[256..],
    );
    builder.connect(
        &[const_zero[0]; 256],
        &pms_opad.input(1).expect("nbit_xor missing input 1")[..256],
    );
    builder.connect(
        &pms_opad.output(0).expect("nbit_xor missing output 0")[..],
        &sha256_opad.input(0).expect("sha256 missing input 0")[..],
    );
    // map SHA256 initial state
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &sha256_opad.input(1).expect("sha256 missing input 1")[..],
        &SHA256_STATE
            .iter()
            .rev()
            .map(|chunk| chunk.to_le_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    );

    // mask inner
    builder.connect(
        &sha256_ipad.output(0).expect("sha256 missing output 0")[..],
        &masked_inner.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_inner[..],
        &masked_inner.input(1).expect("nbit_xor missing input 1")[..],
    );

    // mask outer
    builder.connect(
        &sha256_opad.output(0).expect("sha256 missing output 0")[..],
        &masked_outer.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_outer[..],
        &masked_outer.input(1).expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let out_inner = builder.add_output(
        "MASKED_I",
        "32-byte masked HMAC inner hash state",
        ValueType::Bytes,
        256,
    );
    let out_outer = builder.add_output(
        "MASKED_O",
        "32-byte masked HMAC outer hash state",
        ValueType::Bytes,
        256,
    );

    builder.connect(
        &masked_inner.output(0).expect("nbit_xor missing output 0")[..],
        &out_inner[..],
    );
    builder.connect(
        &masked_outer.output(0).expect("nbit_xor missing output 0")[..],
        &out_outer[..],
    );

    builder.build_circuit().expect("failed to build c1")
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
    fn test_c1() {
        let circ = c1();
        // Perform in the clear all the computations which happen inside the ciruit:
        let mut rng = thread_rng();

        let p = BigUint::parse_bytes(P.as_bytes(), 16).unwrap();
        let share_a = rng.gen_biguint_below(&p);
        let share_b = rng.gen_biguint_below(&p);

        // * generate user's and notary's inside-the-GC-masks to mask the GC output
        let mask_n: [u8; 32] = rng.gen();
        let mask_u: [u8; 32] = rng.gen();

        // reduce pms mod prime if necessary
        let pms = (share_a.clone() + share_b.clone()) % p;

        // * XOR pms (zero-padded to 64 bytes) with inner/outer padding of HMAC
        let mut pms_zeropadded = [0u8; 64];
        pms_zeropadded[0..32].copy_from_slice(&pms.to_bytes_be());

        let pms_ipad = pms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();
        let pms_opad = pms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();

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
        let expected_inner = ihash_state_u8
            .into_iter()
            .zip(mask_u)
            .map(|(b, mask)| b ^ mask)
            .collect::<Vec<u8>>();
        let expected_outer = ohash_state_u8
            .into_iter()
            .zip(mask_n)
            .map(|(b, mask)| b ^ mask)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(share_a.to_bytes_le().to_vec()),
                Value::Bytes(share_b.to_bytes_le().to_vec()),
                Value::Bytes(mask_u.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(mask_n.iter().rev().copied().collect::<Vec<u8>>()),
            ],
            &[
                Value::Bytes(expected_inner.into_iter().rev().collect()),
                Value::Bytes(expected_outer.into_iter().rev().collect()),
            ],
        );
    }
}
