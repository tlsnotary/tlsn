use std::cell::RefCell;

use mpz_circuits::{
    types::{U32, U8},
    BuilderState, Tracer,
};

use crate::{
    hmac_sha256::{hmac_sha256_partial, hmac_sha256_partial_trace},
    prf::{prf, prf_trace},
};

/// Session Keys.
///
/// Computes expanded p1 which consists of client_write_key + server_write_key.
/// Computes expanded p2 which consists of client_IV + server_IV.
///
/// # Arguments
///
/// * `builder_state`   - Reference to builder state.
/// * `pms`             - 32-byte premaster secret.
/// * `client_random`   - 32-byte client random.
/// * `server_random`   - 32-byte server random.
///
/// # Returns
///
/// * `client_write_key`    - 16-byte client write key.
/// * `server_write_key`    - 16-byte server write key.
/// * `client_IV`           - 4-byte client IV.
/// * `server_IV`           - 4-byte server IV.
/// * `outer_hash_state`    - 256-bit master-secret outer HMAC state.
/// * `inner_hash_state`    - 256-bit master-secret inner HMAC state.
#[allow(clippy::type_complexity)]
pub fn session_keys_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    pms: [Tracer<'a, U8>; 32],
    client_random: [Tracer<'a, U8>; 32],
    server_random: [Tracer<'a, U8>; 32],
) -> (
    [Tracer<'a, U8>; 16],
    [Tracer<'a, U8>; 16],
    [Tracer<'a, U8>; 4],
    [Tracer<'a, U8>; 4],
    [Tracer<'a, U32>; 8],
    [Tracer<'a, U32>; 8],
) {
    let (pms_outer_state, pms_inner_state) = hmac_sha256_partial_trace(builder_state, &pms);

    let master_secret = {
        let seed = client_random
            .iter()
            .chain(&server_random)
            .copied()
            .collect::<Vec<_>>();

        let label = b"master secret"
            .map(|v| Tracer::new(builder_state, builder_state.borrow_mut().get_constant(v)));

        prf_trace(
            builder_state,
            pms_outer_state,
            pms_inner_state,
            &seed,
            &label,
            48,
        )
    };

    let (master_secret_outer_state, master_secret_inner_state) =
        hmac_sha256_partial_trace(builder_state, &master_secret);

    let key_material = {
        let seed = server_random
            .iter()
            .chain(&client_random)
            .copied()
            .collect::<Vec<_>>();

        let label = b"key expansion"
            .map(|v| Tracer::new(builder_state, builder_state.borrow_mut().get_constant(v)));

        prf_trace(
            builder_state,
            master_secret_outer_state,
            master_secret_inner_state,
            &seed,
            &label,
            40,
        )
    };

    let cwk = key_material[0..16].try_into().unwrap();
    let swk = key_material[16..32].try_into().unwrap();
    let civ = key_material[32..36].try_into().unwrap();
    let siv = key_material[36..40].try_into().unwrap();

    (
        cwk,
        swk,
        civ,
        siv,
        master_secret_outer_state,
        master_secret_inner_state,
    )
}

/// Reference implementation of session keys derivation.
pub fn session_keys(
    pms: [u8; 32],
    client_random: [u8; 32],
    server_random: [u8; 32],
) -> ([u8; 16], [u8; 16], [u8; 4], [u8; 4]) {
    let (pms_outer_state, pms_inner_state) = hmac_sha256_partial(&pms);

    let master_secret = {
        let seed = client_random
            .iter()
            .chain(&server_random)
            .copied()
            .collect::<Vec<_>>();

        let label = b"master secret";

        prf(pms_outer_state, pms_inner_state, &seed, label, 48)
    };

    let (master_secret_outer_state, master_secret_inner_state) =
        hmac_sha256_partial(&master_secret);

    let key_material = {
        let seed = server_random
            .iter()
            .chain(&client_random)
            .copied()
            .collect::<Vec<_>>();

        let label = b"key expansion";

        prf(
            master_secret_outer_state,
            master_secret_inner_state,
            &seed,
            label,
            40,
        )
    };

    let cwk = key_material[0..16].try_into().unwrap();
    let swk = key_material[16..32].try_into().unwrap();
    let civ = key_material[32..36].try_into().unwrap();
    let siv = key_material[36..40].try_into().unwrap();

    (cwk, swk, civ, siv)
}

#[cfg(test)]
mod tests {
    use mpz_circuits::{evaluate, CircuitBuilder};

    use super::*;

    #[test]
    fn test_session_keys() {
        let builder = CircuitBuilder::new();
        let pms = builder.add_array_input::<u8, 32>();
        let client_random = builder.add_array_input::<u8, 32>();
        let server_random = builder.add_array_input::<u8, 32>();
        let (cwk, swk, civ, siv, outer_state, inner_state) =
            session_keys_trace(builder.state(), pms, client_random, server_random);
        builder.add_output(cwk);
        builder.add_output(swk);
        builder.add_output(civ);
        builder.add_output(siv);
        builder.add_output(outer_state);
        builder.add_output(inner_state);
        let circ = builder.build().unwrap();

        let pms = [0u8; 32];
        let client_random = [42u8; 32];
        let server_random = [69u8; 32];

        let (expected_cwk, expected_swk, expected_civ, expected_siv) =
            session_keys(pms, client_random, server_random);

        let (cwk, swk, civ, siv, _, _) = evaluate!(
            circ,
            fn(
                pms,
                client_random,
                server_random,
            ) -> ([u8; 16], [u8; 16], [u8; 4], [u8; 4], [u32; 8], [u32; 8])
        )
        .unwrap();

        assert_eq!(cwk, expected_cwk);
        assert_eq!(swk, expected_swk);
        assert_eq!(civ, expected_civ);
        assert_eq!(siv, expected_siv);
    }
}
