use std::sync::Arc;

use futures::lock::Mutex;
use hmac_sha256_core::{MasterSecretStateLabels, PmsLabels, MS};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, GCError};
use mpc_circuits::{Value, WireGroup};
use mpc_core::garble::{
    exec::dual::DESummary, ActiveEncodedInput, ChaChaEncoder, Encoder, FullEncodedInput,
    FullInputSet,
};

/// Executes master secret circuit as PRFLeader
///
/// Returns master secret hash state labels
pub async fn leader_ms<DE: DEExecute>(
    leader: DE,
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    pms_labels: PmsLabels,
    client_random: [u8; 32],
    server_random: [u8; 32],
) -> Result<MasterSecretStateLabels, GCError> {
    let inputs = MS.inputs();

    let client_random = inputs[1]
        .clone()
        .to_value(Value::Bytes(client_random.to_vec()))
        .expect("client_random should be 32 bytes");
    let server_random = inputs[2]
        .clone()
        .to_value(Value::Bytes(server_random.to_vec()))
        .expect("server_random should be 32 bytes");
    let const_zero = inputs[3]
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one = inputs[4]
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let (gen_labels, cached_labels) = build_labels(encoder, encoder_stream_id, pms_labels).await;

    let summary = leader
        .execute_skip_equality_check(
            gen_labels,
            vec![
                client_random.clone(),
                server_random.clone(),
                const_zero,
                const_one,
            ],
            vec![],
            vec![client_random, server_random],
            cached_labels,
        )
        .await?;

    let labels = build_ms_labels(summary);

    Ok(labels)
}

/// Executes master secret circuit as PRFFollower
///
/// Returns master secret hash state labels
pub async fn follower_ms<DE: DEExecute>(
    follower: DE,
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    pms_labels: PmsLabels,
) -> Result<MasterSecretStateLabels, GCError> {
    let inputs = MS.inputs();

    let client_random = inputs[1].clone();
    let server_random = inputs[2].clone();
    let const_zero = inputs[3]
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one = inputs[4]
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let (gen_labels, cached_labels) = build_labels(encoder, encoder_stream_id, pms_labels).await;

    let summary = follower
        .execute_skip_equality_check(
            gen_labels,
            vec![const_zero, const_one],
            vec![client_random, server_random],
            vec![],
            cached_labels,
        )
        .await?;

    let labels = build_ms_labels(summary);

    Ok(labels)
}

async fn build_labels(
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    pms_labels: PmsLabels,
) -> (FullInputSet, Vec<ActiveEncodedInput>) {
    let [pms, client_random, server_random, const_zero, const_one] = MS.inputs() else {
        panic!("MS circuit should have 5 inputs");
    };

    let mut encoder = encoder.lock().await;
    let delta = encoder.get_delta();
    let rng = encoder.get_stream(encoder_stream_id);

    let full_pms =
        FullEncodedInput::from_labels(pms.clone(), pms_labels.full).expect("pms should be valid");
    let full_client_random = FullEncodedInput::generate(rng, client_random.clone(), delta);
    let full_server_random = FullEncodedInput::generate(rng, server_random.clone(), delta);
    let full_const_zero = FullEncodedInput::generate(rng, const_zero.clone(), delta);
    let full_const_one = FullEncodedInput::generate(rng, const_one.clone(), delta);

    let gen_labels = FullInputSet::new(vec![
        full_pms,
        full_client_random,
        full_server_random,
        full_const_zero,
        full_const_one,
    ])
    .expect("Labels should be valid");

    let pms_labels = ActiveEncodedInput::from_active_labels(pms.clone(), pms_labels.active)
        .expect("pms should be 32 bytes");

    (gen_labels, vec![pms_labels])
}

fn build_ms_labels(summary: DESummary) -> MasterSecretStateLabels {
    let full_input_labels = summary.get_generator_summary().input_labels();
    let full_output_labels = summary.get_generator_summary().output_labels();
    let active_input_labels = summary.get_evaluator_summary().input_labels();
    let active_output_labels = summary.get_evaluator_summary().output_labels();

    MasterSecretStateLabels {
        full_outer_hash_state: full_output_labels[0].clone().into_labels(),
        full_inner_hash_state: full_output_labels[1].clone().into_labels(),
        active_outer_hash_state: active_output_labels[0].clone().into_labels(),
        active_inner_hash_state: active_output_labels[1].clone().into_labels(),
        full_client_random: full_input_labels[1].clone().into_labels(),
        full_server_random: full_input_labels[2].clone().into_labels(),
        active_client_random: active_input_labels[1].clone().into_labels(),
        active_server_random: active_input_labels[2].clone().into_labels(),
        full_const_zero: full_input_labels[3].clone().into_labels(),
        full_const_one: full_input_labels[4].clone().into_labels(),
        active_const_zero: active_input_labels[3].clone().into_labels(),
        active_const_one: active_input_labels[4].clone().into_labels(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpc_aio::protocol::garble::exec::dual::mock::mock_dualex_pair;
    use mpc_core::garble::exec::dual::DualExConfigBuilder;

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_ms() {
        let de_config = DualExConfigBuilder::default()
            .id("test".to_string())
            .circ(MS.clone())
            .build()
            .expect("DE config should be valid");
        let (gc_leader, gc_follower) = mock_dualex_pair(de_config);

        let pms = [42u8; 32];
        let client_random = [69u8; 32];
        let server_random = [96u8; 32];

        let seed = client_random
            .iter()
            .chain(&server_random)
            .copied()
            .collect::<Vec<u8>>();

        let ms = hmac_sha256_utils::prf(&pms, b"master secret", &seed, 48);

        let (expected_outer_state, expected_inner_state) = hmac_sha256_utils::partial_hmac(&ms);

        todo!()
    }
}
