use std::sync::Arc;

use futures::lock::Mutex;
use hmac_sha256_core::MasterSecretStateLabels;
use mpc_aio::protocol::garble::{exec::dual::DEExecute, GCError};
use mpc_circuits::{Circuit, Value, WireGroup};
use mpc_core::garble::{
    ActiveEncodedInput, ChaChaEncoder, Encoder, FullEncodedInput, FullInputSet,
};
use rand::Rng;

/// Executes pms as PRFLeader
///
/// Returns inner_hash_state
pub async fn leader_verify_data<DE: DEExecute>(
    leader: DE,
    circ: &Circuit,
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    ms_state_labels: MasterSecretStateLabels,
    handshake_hash: [u8; 32],
) -> Result<[u8; 12], GCError> {
    let [_, _, handshake_hash_input, mask_input, const_zero, const_one] = circ.inputs() else {
        panic!("Verify data circuit should have 6 inputs");
    };

    let handshake_hash_value = handshake_hash_input
        .clone()
        .to_value(handshake_hash.iter().copied().rev().collect::<Vec<u8>>())
        .expect("handshake_hash should be 32 bytes");
    let mask: Vec<u8> = rand::thread_rng().gen::<[u8; 12]>().to_vec();
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

    let (gen_labels, cached_labels) =
        build_labels(circ, encoder, encoder_stream_id, ms_state_labels).await;

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
            cached_labels,
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
        .collect::<Vec<u8>>();

    Ok(vd.try_into().expect("verify_data should be 12 bytes"))
}

/// Executes verify_data as PRFFollower
pub async fn follower_verify_data<DE: DEExecute>(
    follower: DE,
    circ: &Circuit,
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    ms_state_labels: MasterSecretStateLabels,
) -> Result<(), GCError> {
    let [_, _, handshake_hash_input, mask_input, const_zero, const_one] = circ.inputs() else {
        panic!("Verify data circuit should have 6 inputs");
    };

    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let (gen_labels, cached_labels) =
        build_labels(circ, encoder, encoder_stream_id, ms_state_labels).await;

    _ = follower
        .execute(
            gen_labels,
            vec![const_zero_value, const_one_value],
            vec![handshake_hash_input.clone(), mask_input.clone()],
            vec![],
            cached_labels,
        )
        .await?;

    Ok(())
}

async fn build_labels(
    circ: &Circuit,
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    ms_state_labels: MasterSecretStateLabels,
) -> (FullInputSet, Vec<ActiveEncodedInput>) {
    let [ms_outer_hash_state, ms_inner_hash_state, handshake_hash, mask, const_zero, const_one] = circ.inputs() else {
        panic!("Verify data circuit should have 6 inputs");
    };

    let full_ms_outer_hash_state_labels = FullEncodedInput::from_labels(
        ms_outer_hash_state.clone(),
        ms_state_labels.full_outer_hash_state.clone(),
    )
    .expect("ms_outer_hash_state_labels should be valid");

    let full_ms_inner_hash_state_labels = FullEncodedInput::from_labels(
        ms_inner_hash_state.clone(),
        ms_state_labels.full_inner_hash_state.clone(),
    )
    .expect("ms_inner_hash_state_labels should be valid");

    let mut encoder = encoder.lock().await;
    let delta = encoder.get_delta();
    let rng = encoder.get_stream(encoder_stream_id);

    let handshake_hash_labels = FullEncodedInput::generate(rng, handshake_hash.clone(), delta);
    let mask_labels = FullEncodedInput::generate(rng, mask.clone(), delta);
    let const_zero_labels = FullEncodedInput::generate(rng, const_zero.clone(), delta);
    let const_one_labels = FullEncodedInput::generate(rng, const_one.clone(), delta);

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
        ms_state_labels.active_outer_hash_state.clone(),
    )
    .expect("ms_outer_hash_state_labels should be valid");

    let active_ms_inner_hash_state_labels = ActiveEncodedInput::from_labels(
        ms_inner_hash_state.clone(),
        ms_state_labels.active_inner_hash_state.clone(),
    )
    .expect("ms_inner_hash_state_labels should be valid");

    (
        gen_labels,
        vec![
            active_ms_outer_hash_state_labels,
            active_ms_inner_hash_state_labels,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::mock::create_mock_ms_state_labels;
    use hmac_sha256_core::CF_VD;
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
        let client_random = [42u8; 32];
        let server_random = [43u8; 32];
        let hs_hash = [99u8; 32];

        let ((leader_labels, follower_labels), (leader_encoder, follower_encoder)) =
            create_mock_ms_state_labels(ms, client_random, server_random);

        let expected_vd = hmac_sha256_utils::prf(&ms, b"client finished", &hs_hash, 12);

        let (vd, _) = tokio::try_join!(
            leader_verify_data(
                gc_leader,
                &CF_VD,
                Arc::new(Mutex::new(leader_encoder)),
                0,
                leader_labels,
                hs_hash
            ),
            follower_verify_data(
                gc_follower,
                &CF_VD,
                Arc::new(Mutex::new(follower_encoder)),
                0,
                follower_labels
            )
        )
        .unwrap();

        assert_eq!(vd.to_vec(), expected_vd);
    }
}
