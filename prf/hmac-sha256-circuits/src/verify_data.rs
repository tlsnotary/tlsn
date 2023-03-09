use std::sync::Arc;

use crate::hmac_sha256::hmac_sha256;
use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder},
    circuits::nbit_xor,
    BitOrder, Circuit, ValueType,
};

/// Compute verify_data
///
/// Inputs:
///
///   0. OUTER_STATE: 32-byte MS outer-hash state H(ms ⊕ opad)
///   1. INNER_STATE: 32-byte MS inner-hash state H(ms ⊕ ipad)
///   2. HS_HASH: 32-byte handshake hash
///   3. MASK: 12-byte mask for verify_data
///
/// Outputs:
///
///   0. MASKED_VD: 12-byte masked verify_data (VD + MASK)
pub fn verify_data(label: &[u8]) -> Arc<Circuit> {
    let label = label.to_vec();
    let label_len = label.len() * 8;

    let mut builder = CircuitBuilder::new("verify_data", "", "0.1.0", BitOrder::Msb0);

    let ms_outer_hash_state = builder.add_input(
        "OUTER_STATE",
        "32-byte MS outer-hash state H(ms ⊕ opad)",
        ValueType::Bytes,
        256,
    );
    let ms_inner_hash_state = builder.add_input(
        "INNER_STATE",
        "32-byte MS inner-hash state H(ms ⊕ ipad)",
        ValueType::Bytes,
        256,
    );
    let hs_hash = builder.add_input("HS_HASH", "32-byte handshake hash", ValueType::Bytes, 256);
    let mask = builder.add_input("MASK", "12-byte mask for verify_data", ValueType::Bytes, 96);
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

    let hmac_a1_circ = hmac_sha256(label.len() + 32);
    let hmac_p1_circ = hmac_sha256(label.len() + 64);
    let xor_96_circ = nbit_xor(96);

    let a1_circ = builder.add_circ(&hmac_a1_circ);
    let p1_circ = builder.add_circ(&hmac_p1_circ);
    let xor = builder.add_circ(&xor_96_circ);

    // Compute a1 = H((k ⊕ opad) || H((k ⊕ ipad) || label || hs_hash))
    let a1 = {
        let msg = a1_circ.input(0).expect("hmac_sha256 missing input 0");
        let a1_outer_state = a1_circ.input(1).expect("hmac_sha256 missing input 1");
        let a1_inner_state = a1_circ.input(2).expect("hmac_sha256 missing input 2");
        let a1_const_zero = a1_circ.input(3).expect("hmac_sha256 missing input 3");
        let a1_const_one = a1_circ.input(4).expect("hmac_sha256 missing input 4");

        // map label
        map_bytes(
            &mut builder,
            BitOrder::Msb0,
            const_zero[0],
            const_one[0],
            &msg[..label_len],
            &label,
        );
        // map hash
        builder.connect(&hs_hash[..], &msg[label_len..]);
        // map outer hash state
        builder.connect(&ms_outer_hash_state[..], &a1_outer_state[..]);
        // map inner hash state
        builder.connect(&ms_inner_hash_state[..], &a1_inner_state[..]);
        // map constant 0
        builder.connect(&const_zero[..], &a1_const_zero[..]);
        // map constant 1
        builder.connect(&const_one[..], &a1_const_one[..]);

        a1_circ.output(0).expect("hmac_sha256 missing output 0")
    };

    // Compute p1 = H((k ⊕ opad) || H((k ⊕ ipad) || a1 || label || hs_hash))
    let p1 = {
        let msg = p1_circ.input(0).expect("hmac_sha256 missing input 0");
        let p1_outer_state = p1_circ.input(1).expect("hmac_sha256 missing input 1");
        let p1_inner_state = p1_circ.input(2).expect("hmac_sha256 missing input 2");
        let p1_const_zero = p1_circ.input(3).expect("hmac_sha256 missing input 3");
        let p1_const_one = p1_circ.input(4).expect("hmac_sha256 missing input 4");

        // map a1
        builder.connect(&a1[..], &msg[..256]);
        // map label
        map_bytes(
            &mut builder,
            BitOrder::Msb0,
            const_zero[0],
            const_one[0],
            &msg[256..256 + label_len],
            &label,
        );
        // map hash
        builder.connect(&hs_hash[..], &msg[256 + label_len..]);
        // map outer hash state
        builder.connect(&ms_outer_hash_state[..], &p1_outer_state[..]);
        // map inner hash state
        builder.connect(&ms_inner_hash_state[..], &p1_inner_state[..]);
        // map constant 0
        builder.connect(&const_zero[..], &p1_const_zero[..]);
        // map constant 1
        builder.connect(&const_one[..], &p1_const_one[..]);

        p1_circ.output(0).expect("hmac_sha256 missing output 0")
    };

    // Apply mask to vd
    let masked_vd = {
        // vd == p1[..96]
        builder.connect(
            &p1[..96],
            &xor.input(0).expect("nbit_xor missing input 0")[..],
        );
        builder.connect(
            &mask[..],
            &xor.input(1).expect("nbit_xor missing input 1")[..],
        );
        xor.output(0).expect("nbit_xor missing output 0")
    };

    let mut builder = builder.build_gates();

    let out_masked_vd = builder.add_output(
        "MASKED_VD",
        "12-byte masked verify_data",
        ValueType::Bytes,
        96,
    );

    builder.connect(&masked_vd[..], &out_masked_vd[..]);

    builder
        .build_circuit()
        .expect("failed to build verify_data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{partial_sha256_digest, test_circ};
    use mpc_circuits::Value;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    const CF_LABEL: &[u8; 15] = b"client finished";

    fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(input);
        let out = mac.finalize().into_bytes();
        out[..32]
            .try_into()
            .expect("expected output to be 32 bytes")
    }

    fn compute_client_finished_vd(ms: [u8; 48], handshake_hash: [u8; 32]) -> [u8; 12] {
        let mut seed = [0u8; 47];
        seed[..15].copy_from_slice(CF_LABEL);
        seed[15..].copy_from_slice(&handshake_hash);
        let a1 = hmac_sha256(&ms, &seed);

        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let p1 = hmac_sha256(&ms, &a1_seed);

        let mut vd = [0u8; 12];
        vd.copy_from_slice(&p1[..12]);

        vd
    }

    #[test]
    #[ignore = "expensive"]
    fn test_verify_data() {
        let circ = verify_data(CF_LABEL);

        let ms = [254u8; 48];
        let mask = [249u8; 12];
        let hs_hash = [99u8; 32];

        let mut ms_zeropadded = [0u8; 64];
        ms_zeropadded[..48].copy_from_slice(&ms);

        let ms_opad = ms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let ms_ipad = ms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        let ms_outer_hash_state = partial_sha256_digest(&ms_opad);
        let ms_inner_hash_state = partial_sha256_digest(&ms_ipad);

        let vd = compute_client_finished_vd(ms, hs_hash);

        let vd_masked = vd
            .iter()
            .zip(mask.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    ms_outer_hash_state
                        .into_iter()
                        .map(|v| v.to_be_bytes())
                        .flatten()
                        .collect::<Vec<u8>>(),
                ),
                Value::Bytes(
                    ms_inner_hash_state
                        .into_iter()
                        .map(|v| v.to_be_bytes())
                        .flatten()
                        .collect::<Vec<u8>>(),
                ),
                Value::Bytes(hs_hash.to_vec()),
                Value::Bytes(mask.to_vec()),
            ],
            &[Value::Bytes(vd_masked)],
        );
    }
}
