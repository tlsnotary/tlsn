use std::sync::Arc;

use mpc_circuits::{builder::CircuitBuilder, BitOrder, Circuit, ValueType};

use crate::sha256_finalize;

/// Session Keys
///
/// Compute expanded p1 which consists of client_write_key + server_write_key
/// Compute expanded p2 which consists of client_IV + server_IV
///
/// Inputs:
///
///   0. OUTER_HASH_STATE: 32-byte outer-hash state
///   1. P1_INNER: 32-byte inner hash for p1_expanded_keys
///   2. P2_INNER: 32-byte inner hash for p2_expanded_keys
///
/// Outputs:
///
///   0. CWK: 16-byte client write-key
///   1. SWK: 16-byte server write-key
///   2. CIV: 4-byte client IV
///   3. SIV: 4-byte server IV
pub fn session_keys() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("session_keys", "", "0.1.0", BitOrder::Msb0);

    let outer_state = builder.add_input(
        "OUTER_HASH_STATE",
        "32-byte hash state",
        ValueType::Bytes,
        256,
    );
    let p1_hash = builder.add_input(
        "P1_INNER",
        "32-byte inner hash for p1_expanded_keys",
        ValueType::Bytes,
        256,
    );
    let p2_hash = builder.add_input(
        "P2_INNER",
        "32-byte inner hash for p2_expanded_keys",
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

    let sha256_circ = sha256_finalize(64, 32);

    let p1_circ = builder.add_circ(&sha256_circ);
    let p2_circ = builder.add_circ(&sha256_circ);

    // Compute p1
    let p1 = {
        let msg = p1_circ.input(0).expect("sha256 missing input 0");
        let state = p1_circ.input(1).expect("sha256 missing input 1");
        let p1_const_zero = p1_circ.input(2).expect("sha256 missing input 2");
        let p1_const_one = p1_circ.input(3).expect("sha256 missing input 3");

        // map the inner hash
        builder.connect(&p1_hash[..], &msg[..]);
        // map state
        builder.connect(&outer_state[..], &state[..]);
        // map constant 0
        builder.connect(&const_zero[..], &p1_const_zero[..]);
        // map constant 1
        builder.connect(&const_one[..], &p1_const_one[..]);

        p1_circ.output(0).expect("sha256 missing output 0")
    };

    // Compute p2
    let p2 = {
        let msg = p2_circ.input(0).expect("sha256 missing input 0");
        let state = p2_circ.input(1).expect("sha256 missing input 1");
        let p2_const_zero = p2_circ.input(2).expect("sha256 missing input 2");
        let p2_const_one = p2_circ.input(3).expect("sha256 missing input 3");

        // map the inner hash
        builder.connect(&p2_hash[..], &msg[..]);
        // map state
        builder.connect(&outer_state[..], &state[..]);
        // map constant 0
        builder.connect(&const_zero[..], &p2_const_zero[..]);
        // map constant 1
        builder.connect(&const_one[..], &p2_const_one[..]);

        p2_circ.output(0).expect("sha256 missing output 0")
    };

    let mut builder = builder.build_gates();

    let cwk = builder.add_output("CWK", "16-byte client write-key", ValueType::Bytes, 128);
    let swk = builder.add_output("SWK", "16-byte server write-key", ValueType::Bytes, 128);
    let civ = builder.add_output("CIV", "4-byte client IV", ValueType::Bytes, 32);
    let siv = builder.add_output("SIV", "4-byte server IV", ValueType::Bytes, 32);

    builder.connect(&p1[..128], &cwk[..]);

    builder.connect(&p1[128..], &swk[..]);

    builder.connect(&p2[..32], &civ[..]);

    builder.connect(&p2[32..64], &siv[..]);

    builder
        .build_circuit()
        .expect("failed to build session_keys")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{finalize_sha256_digest, test_circ};
    use mpc_circuits::Value;
    use rand::{thread_rng, Rng};

    #[test]
    #[ignore = "expensive"]
    fn test_session_keys() {
        let circ = session_keys();
        // Perform in the clear all the computations which happen inside the ciruit:
        let mut rng = thread_rng();

        let n_outer_hash_state: [u32; 8] = rng.gen();
        let u_inner_hash_p1: [u8; 32] = rng.gen();
        let u_inner_hash_p2: [u8; 32] = rng.gen();

        // finalize the hash to get p1
        let p1 = finalize_sha256_digest(n_outer_hash_state, 64, &u_inner_hash_p1);
        // finalize the hash to get p2
        let p2 = finalize_sha256_digest(n_outer_hash_state, 64, &u_inner_hash_p2);

        // get expanded_keys (TLS session keys)
        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..40].copy_from_slice(&p2[0..8]);
        // split into client/server_write_key and client/server_write_iv
        let mut cwk = [0u8; 16];
        cwk.copy_from_slice(&ek[0..16]);
        let mut swk = [0u8; 16];
        swk.copy_from_slice(&ek[16..32]);
        let mut civ = [0u8; 4];
        civ.copy_from_slice(&ek[32..36]);
        let mut siv = [0u8; 4];
        siv.copy_from_slice(&ek[36..40]);

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
                Value::Bytes(u_inner_hash_p2.to_vec()),
            ],
            &[
                Value::Bytes(cwk.to_vec()),
                Value::Bytes(swk.to_vec()),
                Value::Bytes(civ.to_vec()),
                Value::Bytes(siv.to_vec()),
            ],
        );
    }
}
