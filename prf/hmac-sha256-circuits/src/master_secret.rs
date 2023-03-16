use std::sync::Arc;

use mpc_circuits::{builder::CircuitBuilder, BitOrder, Circuit, ValueType};
use utils::bits::IterToBits;

use crate::{add_hmac_sha256_partial, add_prf};

/// Master secret
///
/// Computes the master secret (MS), returning the outer and inner HMAC states.
///
/// Outer state is H(master_secret ⊕ opad)
///
/// Inner state is H(master_secret ⊕ ipad)
///
/// Inputs:
///
///   0. PMS: 32-byte pre-master secret
///   1. CLIENT_RAND: 32-byte client random
///   2. SERVER_RAND: 32-byte server random
///
/// Outputs:
///
///   0. OUTER_STATE: 32-byte HMAC outer hash state
///   1. INNER_STATE: 32-byte HMAC inner hash state
pub fn master_secret() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("master_secret", "", "0.1.0", BitOrder::Msb0);

    let pms = builder.add_input("PMS", "32-byte PMS, big endian", ValueType::Bytes, 256);
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

    let (pms_outer_state, pms_inner_state) =
        add_hmac_sha256_partial(&mut builder, &pms[..], &const_zero[0], &const_one[0]);

    let label = b"master secret"
        .into_msb0_iter()
        .map(|bit| if bit { const_one[0] } else { const_zero[0] })
        .collect::<Vec<_>>();
    let seed = client_random[..]
        .iter()
        .chain(&server_random[..])
        .copied()
        .collect::<Vec<_>>();

    let ms = add_prf(
        &mut builder,
        &pms_outer_state,
        &pms_inner_state,
        &const_zero[0],
        &const_one[0],
        &label,
        &seed,
        48,
    );

    let (ms_outer_state, ms_inner_state) =
        add_hmac_sha256_partial(&mut builder, &ms, &const_zero[0], &const_one[0]);

    let mut builder = builder.build_gates();

    let outer_state = builder.add_output(
        "OUTER_STATE",
        "32-byte HMAC outer hash state",
        ValueType::Bytes,
        256,
    );

    builder.connect(&ms_outer_state[..], &outer_state[..]);

    let inner_state = builder.add_output(
        "INNER_STATE",
        "32-byte HMAC inner hash state",
        ValueType::Bytes,
        256,
    );

    builder.connect(&ms_inner_state[..], &inner_state[..]);

    builder
        .build_circuit()
        .expect("failed to build master_secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_helpers::test_circ;
    use hmac_sha256_utils::{partial_hmac, prf};
    use mpc_circuits::Value;

    #[test]
    #[ignore = "expensive"]
    fn test_master_secret() {
        let circ = master_secret();

        println!("MS Circuit size: {}", circ.and_count());

        let pms = [69u8; 32];
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];

        let seed = client_random
            .iter()
            .chain(&server_random)
            .copied()
            .collect::<Vec<_>>();

        let ms = prf(&pms, b"master secret", &seed, 48);

        let (expected_outer_state, expected_inner_state) = partial_hmac(&ms);

        let expected_outer_state = expected_outer_state
            .into_iter()
            .map(|v| v.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let expected_inner_state = expected_inner_state
            .into_iter()
            .map(|v| v.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(pms.to_vec()),
                Value::Bytes(client_random.to_vec()),
                Value::Bytes(server_random.to_vec()),
            ],
            &[
                Value::Bytes(expected_outer_state),
                Value::Bytes(expected_inner_state),
            ],
        );
    }
}
