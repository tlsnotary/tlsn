use std::cell::RefCell;

use mpz_circuits::{
    types::{U32, U8},
    BuilderState, Tracer,
};

use crate::prf::{prf, prf_trace};

/// Computes verify_data as specified in RFC 5246, Section 7.4.9.
///
/// verify_data
///   PRF(master_secret, finished_label,
/// Hash(handshake_messages))[0..verify_data_length-1];
///
/// # Arguments
///
/// * `builder_state`   - The builder state.
/// * `outer_state`     - The outer HMAC state of the master secret.
/// * `inner_state`     - The inner HMAC state of the master secret.
/// * `label`           - The label to use.
/// * `hs_hash`         - The handshake hash.
pub fn verify_data_trace<'a>(
    builder_state: &'a RefCell<BuilderState>,
    outer_state: [Tracer<'a, U32>; 8],
    inner_state: [Tracer<'a, U32>; 8],
    label: &[Tracer<'a, U8>],
    hs_hash: [Tracer<'a, U8>; 32],
) -> [Tracer<'a, U8>; 12] {
    let vd = prf_trace(builder_state, outer_state, inner_state, &hs_hash, label, 12);

    vd.try_into().expect("vd is 12 bytes")
}

/// Reference implementation of verify_data as specified in RFC 5246, Section
/// 7.4.9.
///
/// # Arguments
///
/// * `outer_state` - The outer HMAC state of the master secret.
/// * `inner_state` - The inner HMAC state of the master secret.
/// * `label`       - The label to use.
/// * `hs_hash`     - The handshake hash.
pub fn verify_data(
    outer_state: [u32; 8],
    inner_state: [u32; 8],
    label: &[u8],
    hs_hash: [u8; 32],
) -> [u8; 12] {
    let vd = prf(outer_state, inner_state, &hs_hash, label, 12);

    vd.try_into().expect("vd is 12 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_circuits::{evaluate, CircuitBuilder};

    const CF_LABEL: &[u8; 15] = b"client finished";

    #[test]
    fn test_verify_data() {
        let builder = CircuitBuilder::new();
        let outer_state = builder.add_array_input::<u32, 8>();
        let inner_state = builder.add_array_input::<u32, 8>();
        let label = builder.add_array_input::<u8, 15>();
        let hs_hash = builder.add_array_input::<u8, 32>();
        let vd = verify_data_trace(builder.state(), outer_state, inner_state, &label, hs_hash);
        builder.add_output(vd);
        let circ = builder.build().unwrap();

        let outer_state = [0u32; 8];
        let inner_state = [1u32; 8];
        let hs_hash = [42u8; 32];

        let expected = prf(outer_state, inner_state, &hs_hash, CF_LABEL, 12);

        let actual = evaluate!(
            circ,
            fn(outer_state, inner_state, CF_LABEL, hs_hash) -> [u8; 12]
        )
        .unwrap();

        assert_eq!(actual.to_vec(), expected);
    }
}
