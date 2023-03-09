use std::sync::Arc;

use crate::{hmac_pad, sha256_finalize};
use mpc_circuits::{builder::CircuitBuilder, circuits::nbit_xor, BitOrder, Circuit, ValueType};

/// Master secret
///
/// Computes the master secret (MS).
/// Outputs sha256(ms xor opad) called "ms outer hash state" and
/// sha256(ms xor ipad) called "ms inner hash state"
///
/// Inputs:
///
///   0. PMS_O_STATE: 32-byte PMS outer-hash state
///   1. P1_INNER: 32-byte inner hash of P1
///   2. P2: 16-byte P2
///
/// Outputs:
///
///   0. MASKED_O_STATE: 32-byte HMAC outer hash state
///   1. MASKED_I_STATE: 32-byte HMAC inner hash state
pub fn master_secret() -> Arc<Circuit> {
    todo!()
}

//     let mut builder = CircuitBuilder::new("master_secret", "", "0.1.0", BitOrder::Msb0);

//     let pms = builder.add_input("PMS", "32-byte PMS, big endian", ValueType::Bytes, 256);
//     let client_random = builder.add_input(
//         "CLIENT_RAND",
//         "32-byte client random",
//         ValueType::Bytes,
//         256,
//     );
//     let server_random = builder.add_input(
//         "SERVER_RAND",
//         "32-byte server random",
//         ValueType::Bytes,
//         256,
//     );

//     let const_zero = builder.add_input(
//         "const_zero",
//         "input that is always 0",
//         ValueType::ConstZero,
//         1,
//     );
//     let const_one = builder.add_input(
//         "const_one",
//         "input that is always 1",
//         ValueType::ConstOne,
//         1,
//     );

//     let mut builder = builder.build_inputs();

//     let pms_inner_circ = hmac_pad(32, [0x36u8; 64]);
//     let pms_outer_circ = hmac_pad(32, [0x5cu8; 64]);

//     let mut builder = builder.build_gates();

//     let out_outer = builder.add_output(
//         "MASKED_O_STATE",
//         "32-byte masked HMAC outer hash state",
//         ValueType::Bytes,
//         256,
//     );

//     builder.connect(
//         &xor_outer.output(0).expect("xor missing output 0")[..],
//         &out_outer[..],
//     );

//     let out_inner = builder.add_output(
//         "MASKED_I_STATE",
//         "32-byte masked HMAC inner hash state",
//         ValueType::Bytes,
//         256,
//     );

//     builder.connect(
//         &xor_inner.output(0).expect("xor missing output 0")[..],
//         &out_inner[..],
//     );

//     builder
//         .build_circuit()
//         .expect("failed to build master_secret")
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{finalize_sha256_digest, partial_sha256_digest, test_circ};
    use mpc_circuits::Value;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    #[ignore = "expensive"]
    fn test_master_secret() {
        let circ = master_secret();
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let n_outer_hash_state: [u32; 8] = rng.gen();
        let u_inner_hash_p1: [u8; 32] = rng.gen();
        let u_p2: [u8; 16] = rng.gen();
        let mask_inner: [u8; 32] = rng.gen();
        let mask_outer: [u8; 32] = rng.gen();

        // finalize the hash to get p1
        let p1 = finalize_sha256_digest(n_outer_hash_state, 64, &u_inner_hash_p1);
        // get master_secret
        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..].copy_from_slice(&u_p2[..16]);

        // * XOR ms (zero-padded to 64 bytes) with inner/outer padding of HMAC
        let mut ms_zeropadded = [0u8; 64];
        ms_zeropadded[0..48].copy_from_slice(&ms);

        let ms_opad = ms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let ms_ipad = ms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        // * hash the padded PMS
        let ohash_state = partial_sha256_digest(&ms_opad);
        let ihash_state = partial_sha256_digest(&ms_ipad);
        // convert into u8 array
        let expected_outer: Vec<u8> = ohash_state
            .iter()
            .map(|u32t| u32t.to_be_bytes())
            .flatten()
            .zip(mask_outer.iter())
            .map(|(b1, b2)| b1 ^ b2)
            .collect();
        let expected_inner: Vec<u8> = ihash_state
            .iter()
            .map(|u32t| u32t.to_be_bytes())
            .flatten()
            .zip(mask_inner.iter())
            .map(|(b1, b2)| b1 ^ b2)
            .collect();

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    n_outer_hash_state
                        .into_iter()
                        .map(|v| v.to_be_bytes())
                        .flatten()
                        .collect::<Vec<u8>>(),
                ),
                Value::Bytes(u_inner_hash_p1.to_vec()),
                Value::Bytes(u_p2.to_vec()),
                Value::Bytes(mask_outer.to_vec()),
                Value::Bytes(mask_inner.to_vec()),
            ],
            &[Value::Bytes(expected_outer), Value::Bytes(expected_inner)],
        );
    }
}
