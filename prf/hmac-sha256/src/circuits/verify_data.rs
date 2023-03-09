use std::sync::Arc;

use hmac_sha256_core::MasterSecretStateLabels;
use mpc_aio::protocol::garble::{exec::dual::DEExecute, GCError};
use mpc_circuits::{Circuit, Value, WireGroup};
use mpc_core::garble::{ActiveEncodedInput, FullEncodedInput, FullInputSet};
use rand::{thread_rng, Rng};

/// Executes pms as PRFLeader
///
/// Returns inner_hash_state
pub async fn leader_verify_data<DE: DEExecute>(
    leader: DE,
    circ: Arc<Circuit>,
    ms_hash_state_labels: MasterSecretStateLabels,
    handshake_hash: [u8; 32],
) -> Result<[u8; 12], GCError> {
    let delta = ms_hash_state_labels.full_inner_hash_state().get_delta();

    let [ms_outer_hash_state, ms_inner_hash_state, handshake_hash_input, mask_input, const_zero, const_one] = circ.inputs() else {
        panic!("Circuit 1 should have 6 inputs");
    };

    let full_ms_outer_hash_state_labels = FullEncodedInput::from_labels(
        ms_outer_hash_state.clone(),
        ms_hash_state_labels.full_outer_hash_state().clone(),
    )
    .expect("ms_outer_hash_state_labels should be valid");

    let full_ms_inner_hash_state_labels = FullEncodedInput::from_labels(
        ms_inner_hash_state.clone(),
        ms_hash_state_labels.full_inner_hash_state().clone(),
    )
    .expect("ms_inner_hash_state_labels should be valid");

    let handshake_hash_labels =
        FullEncodedInput::generate(&mut thread_rng(), handshake_hash_input.clone(), delta);
    let mask_labels = FullEncodedInput::generate(&mut thread_rng(), mask_input.clone(), delta);
    let const_zero_labels =
        FullEncodedInput::generate(&mut thread_rng(), const_zero.clone(), delta);
    let const_one_labels = FullEncodedInput::generate(&mut thread_rng(), const_one.clone(), delta);

    let gen_labels = FullInputSet::new(vec![
        full_ms_outer_hash_state_labels,
        full_ms_inner_hash_state_labels,
        handshake_hash_labels,
        mask_labels,
        const_zero_labels,
        const_one_labels,
    ])
    .expect("All labels should be valid");

    let active_ms_outer_hash_state_labels = ActiveEncodedInput::from_labels(
        ms_outer_hash_state.clone(),
        ms_hash_state_labels.active_outer_hash_state().clone(),
    )
    .expect("ms_outer_hash_state_labels should be valid");

    let active_ms_inner_hash_state_labels = ActiveEncodedInput::from_labels(
        ms_inner_hash_state.clone(),
        ms_hash_state_labels.active_inner_hash_state().clone(),
    )
    .expect("ms_inner_hash_state_labels should be valid");

    let handshake_hash_value = handshake_hash_input
        .clone()
        .to_value(handshake_hash.iter().copied().rev().collect::<Vec<u8>>())
        .expect("handshake_hash should be 32 bytes");
    let mask: Vec<u8> = thread_rng().gen::<[u8; 12]>().to_vec();
    let mask_value = mask_input
        .clone()
        .to_value(mask.clone())
        .expect("MASK should be 12 bytes");
    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let output = leader
        .execute(
            gen_labels,
            vec![
                handshake_hash_value.clone(),
                mask_value.clone(),
                const_zero_value,
                const_one_value,
            ],
            vec![],
            vec![handshake_hash_value, mask_value],
            vec![
                active_ms_outer_hash_state_labels,
                active_ms_inner_hash_state_labels,
            ],
        )
        .await?;

    let Value::Bytes(masked_vd) = output[0].value().clone() else {
        panic!("verify_data output 0 should be bytes");
    };

    // Remove mask
    let vd = masked_vd
        .iter()
        .zip(mask.iter())
        .map(|(a, b)| a ^ b)
        .rev()
        .collect::<Vec<u8>>();

    Ok(vd.try_into().expect("verify_data should be 12 bytes"))
}

/// Executes verify_data as PRFFollower
pub async fn follower_verify_data<DE: DEExecute>(
    follower: DE,
    circ: Arc<Circuit>,
    ms_hash_state_labels: MasterSecretStateLabels,
) -> Result<(), GCError> {
    let delta = ms_hash_state_labels.full_inner_hash_state().get_delta();

    let [ms_outer_hash_state, ms_inner_hash_state, handshake_hash_input, mask_input, const_zero, const_one] = circ.inputs() else {
        panic!("Circuit 1 should have 6 inputs");
    };

    let full_ms_outer_hash_state_labels = FullEncodedInput::from_labels(
        ms_outer_hash_state.clone(),
        ms_hash_state_labels.full_outer_hash_state().clone(),
    )
    .expect("ms_outer_hash_state_labels should be valid");

    let full_ms_inner_hash_state_labels = FullEncodedInput::from_labels(
        ms_inner_hash_state.clone(),
        ms_hash_state_labels.full_inner_hash_state().clone(),
    )
    .expect("ms_inner_hash_state_labels should be valid");

    let handshake_hash_labels =
        FullEncodedInput::generate(&mut thread_rng(), handshake_hash_input.clone(), delta);
    let mask_labels = FullEncodedInput::generate(&mut thread_rng(), mask_input.clone(), delta);
    let const_zero_labels =
        FullEncodedInput::generate(&mut thread_rng(), const_zero.clone(), delta);
    let const_one_labels = FullEncodedInput::generate(&mut thread_rng(), const_one.clone(), delta);

    let gen_labels = FullInputSet::new(vec![
        full_ms_outer_hash_state_labels,
        full_ms_inner_hash_state_labels,
        handshake_hash_labels,
        mask_labels,
        const_zero_labels,
        const_one_labels,
    ])
    .expect("All labels should be valid");

    let active_ms_outer_hash_state_labels = ActiveEncodedInput::from_labels(
        ms_outer_hash_state.clone(),
        ms_hash_state_labels.active_outer_hash_state().clone(),
    )
    .expect("ms_outer_hash_state_labels should be valid");

    let active_ms_inner_hash_state_labels = ActiveEncodedInput::from_labels(
        ms_inner_hash_state.clone(),
        ms_hash_state_labels.active_inner_hash_state().clone(),
    )
    .expect("ms_inner_hash_state_labels should be valid");

    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    _ = follower
        .execute(
            gen_labels,
            vec![const_zero_value, const_one_value],
            vec![handshake_hash_input.clone(), mask_input.clone()],
            vec![],
            vec![
                active_ms_outer_hash_state_labels,
                active_ms_inner_hash_state_labels,
            ],
        )
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::mock::create_mock_ms_state_labels;
    use hmac_sha256_core::{utils::compute_client_finished_vd, CF_VD};
    use mpc_aio::protocol::garble::exec::dual::mock::mock_dualex_pair;
    use mpc_core::garble::exec::dual::DualExConfigBuilder;

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_vd() {
        let de_config = DualExConfigBuilder::default()
            .id("test".to_string())
            .circ(CF_VD.clone())
            .build()
            .expect("DE config should be valid");
        let (gc_leader, gc_follower) = mock_dualex_pair(de_config);

        let ms = [69u8; 48];
        let hs_hash = [99u8; 32];

        let ((leader_labels, follower_labels), _) = create_mock_ms_state_labels(ms);

        let expected_vd = compute_client_finished_vd(ms, hs_hash);

        let (vd, _) = tokio::join!(
            async move {
                leader_verify_data(gc_leader, CF_VD.clone(), leader_labels, hs_hash)
                    .await
                    .unwrap()
            },
            async move {
                follower_verify_data(gc_follower, CF_VD.clone(), follower_labels)
                    .await
                    .unwrap()
            }
        );

        assert_eq!(vd, expected_vd);
    }
}
