use std::sync::Arc;

use mpc_circuits::{builder::CircuitBuilder, BitOrder, Circuit, ValueType};
use utils::bits::IterToBits;

use crate::add_prf;

/// Session Keys
///
/// Compute expanded p1 which consists of client_write_key + server_write_key
/// Compute expanded p2 which consists of client_IV + server_IV
///
/// Inputs:
///
///   0. OUTER_HASH_STATE: 32-byte MS outer-hash state
///   1. INNER_HASH_STATE: 32-byte MS inner-hash state
///   2. CLIENT_RAND: 32-byte client random
///   3. SERVER_RAND: 32-byte server random
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
        "32-byte MS outer-hash state",
        ValueType::Bytes,
        256,
    );
    let inner_state = builder.add_input(
        "INNER_HASH_STATE",
        "32-byte MS inner-hash state",
        ValueType::Bytes,
        256,
    );
    let client_random = builder.add_input(
        "CLIENT_RAND",
        "32-byte client random",
        ValueType::Bytes,
        256,
    );
    let server_random = builder.add_input(
        "SERVER_RAND",
        "32-byte server random",
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

    let label = b"key expansion"
        .into_msb0_iter()
        .map(|bit| if bit { const_one[0] } else { const_zero[0] })
        .collect::<Vec<_>>();
    let seed = server_random[..]
        .iter()
        .chain(&client_random[..])
        .copied()
        .collect::<Vec<_>>();

    let key_material = add_prf(
        &mut builder,
        &outer_state[..],
        &inner_state[..],
        &const_zero[0],
        &const_one[0],
        &label,
        &seed,
        40,
    );

    let mut builder = builder.build_gates();

    let cwk = builder.add_output("CWK", "16-byte client write-key", ValueType::Bytes, 128);
    let swk = builder.add_output("SWK", "16-byte server write-key", ValueType::Bytes, 128);
    let civ = builder.add_output("CIV", "4-byte client IV", ValueType::Bytes, 32);
    let siv = builder.add_output("SIV", "4-byte server IV", ValueType::Bytes, 32);

    builder.connect(&key_material[..128], &cwk[..]);

    builder.connect(&key_material[128..256], &swk[..]);

    builder.connect(&key_material[256..288], &civ[..]);

    builder.connect(&key_material[288..], &siv[..]);

    builder
        .build_circuit()
        .expect("failed to build session_keys")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_circ;
    use mpc_circuits::Value;

    #[test]
    #[ignore = "expensive"]
    fn test_session_keys() {
        let circ = session_keys();

        println!("KE Circuit size: {}", circ.and_count());

        let ms = [42u8; 48];
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];
        let seed = server_random
            .iter()
            .chain(&client_random)
            .copied()
            .collect::<Vec<_>>();

        let (outer_hash_state, inner_hash_state) = hmac_sha256_utils::partial_hmac(&ms);

        let key_material = hmac_sha256_utils::prf(&ms, b"key expansion", &seed, 40);

        // split into client/server_write_key and client/server_write_iv
        let mut cwk = [0u8; 16];
        cwk.copy_from_slice(&key_material[0..16]);
        let mut swk = [0u8; 16];
        swk.copy_from_slice(&key_material[16..32]);
        let mut civ = [0u8; 4];
        civ.copy_from_slice(&key_material[32..36]);
        let mut siv = [0u8; 4];
        siv.copy_from_slice(&key_material[36..40]);

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    outer_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(
                    inner_hash_state
                        .into_iter()
                        .map(|chunk| chunk.to_be_bytes())
                        .flatten()
                        .collect(),
                ),
                Value::Bytes(client_random.to_vec()),
                Value::Bytes(server_random.to_vec()),
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
