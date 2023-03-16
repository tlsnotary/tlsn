use std::sync::Arc;

use mpc_circuits::{builder::CircuitBuilder, circuits::nbit_xor, BitOrder, Circuit, ValueType};
use utils::bits::IterToBits;

use crate::add_prf;

/// Computes verify_data as specified in RFC 5246, Section 7.4.9.
///
/// verify_data
///   PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1];
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

    let mut builder = CircuitBuilder::new("verify_data", "", "0.1.0", BitOrder::Msb0);

    let outer_hash_state = builder.add_input(
        "OUTER_STATE",
        "32-byte MS outer-hash state H(ms ⊕ opad)",
        ValueType::Bytes,
        256,
    );
    let inner_hash_state = builder.add_input(
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

    let xor = builder.add_circ(&nbit_xor(96));

    let label = label
        .into_msb0_iter()
        .map(|bit| if bit { const_one[0] } else { const_zero[0] })
        .collect::<Vec<_>>();

    let vd = add_prf(
        &mut builder,
        &outer_hash_state[..],
        &inner_hash_state[..],
        &const_zero[0],
        &const_one[0],
        &label,
        &hs_hash[..],
        12,
    );

    // Apply mask to vd
    let masked_vd = {
        builder.connect(&vd, &xor.input(0).expect("nbit_xor missing input 0")[..]);
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
    use mpc_circuits::{circuits::test_circ, Value};

    const CF_LABEL: &[u8; 15] = b"client finished";

    #[test]
    #[ignore = "expensive"]
    fn test_verify_data() {
        let circ = verify_data(CF_LABEL);

        println!("VD Circuit size: {}", circ.and_count());

        let ms = [254u8; 48];
        let mask = [249u8; 12];
        let hs_hash = [99u8; 32];

        let (ms_outer_hash_state, ms_inner_hash_state) = hmac_sha256_utils::partial_hmac(&ms);

        let vd = hmac_sha256_utils::prf(&ms, CF_LABEL, &hs_hash, 12);

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
