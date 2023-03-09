use futures::lock::Mutex;
use std::sync::Arc;

use hmac_sha256_core::{SessionKeyLabels, SESSION_KEYS};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, GCError};
use mpc_circuits::{Value, WireGroup};
use mpc_core::garble::{ChaChaEncoder, Encoder, FullInputSet};

/// Executes session_keys as PRFLeader
///
/// Returns session key shares
pub async fn leader_session_keys<DE: DEExecute>(
    leader: DE,
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    p1_inner_hash: [u8; 32],
    p2_inner_hash: [u8; 32],
) -> Result<SessionKeyLabels, GCError> {
    let circ = SESSION_KEYS.clone();

    let [outer_hash_state_input, p1_inner_input, p2_inner_input,  const_zero, const_one] = circ.inputs() else {
        panic!("Circuit 3 should have 5 inputs");
    };

    let mut encoder = encoder.lock().await;
    let delta = encoder.get_delta();
    let gen_labels = FullInputSet::generate(
        &mut encoder.get_stream(encoder_stream_id),
        &circ,
        Some(delta),
    );
    drop(encoder);

    let p1_inner_hash_value = p1_inner_input
        .clone()
        .to_value(p1_inner_hash.iter().copied().rev().collect::<Vec<u8>>())
        .expect("P1_INNER should be 32 bytes");
    let p2_inner_hash_value = p2_inner_input
        .clone()
        .to_value(p2_inner_hash.iter().copied().rev().collect::<Vec<u8>>())
        .expect("P2_INNER should be 32 bytes");
    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let gen_inputs = vec![
        p1_inner_hash_value.clone(),
        p2_inner_hash_value.clone(),
        const_zero_value,
        const_one_value,
    ];
    let ot_send_inputs = vec![outer_hash_state_input.clone()];
    let ot_receive_inputs = vec![p1_inner_hash_value, p2_inner_hash_value];
    let cached_labels = vec![];

    let de_summary = leader
        .execute_skip_equality_check(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    let full_output_labels = de_summary.get_generator_summary().output_labels();
    let full_cwk = full_output_labels[0].clone().into_labels();
    let full_swk = full_output_labels[1].clone().into_labels();
    let full_civ = full_output_labels[2].clone().into_labels();
    let full_siv = full_output_labels[3].clone().into_labels();

    let active_output_labels = de_summary.get_evaluator_summary().output_labels();
    let active_cwk = active_output_labels[0].clone().into_labels();
    let active_swk = active_output_labels[1].clone().into_labels();
    let active_civ = active_output_labels[2].clone().into_labels();
    let active_siv = active_output_labels[3].clone().into_labels();

    Ok(SessionKeyLabels::new(
        full_cwk, full_swk, full_civ, full_siv, active_cwk, active_swk, active_civ, active_siv,
    ))
}

/// Executes session_keys as PRFFollower
///
/// Returns outer_hash_state
pub async fn follower_session_keys<DE: DEExecute>(
    follower: DE,
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    outer_hash_state: [u32; 8],
) -> Result<SessionKeyLabels, GCError> {
    let circ = SESSION_KEYS.clone();

    let [outer_hash_state_input, p1_inner_input, p2_inner_input,  const_zero, const_one] = circ.inputs() else {
        panic!("Circuit 3 should have 5 inputs");
    };

    let mut encoder = encoder.lock().await;
    let delta = encoder.get_delta();
    let gen_labels = FullInputSet::generate(
        &mut encoder.get_stream(encoder_stream_id),
        &circ,
        Some(delta),
    );
    drop(encoder);

    let outer_hash_state_value = outer_hash_state_input
        .clone()
        .to_value(
            outer_hash_state
                .into_iter()
                .rev()
                .map(|chunk| chunk.to_le_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        )
        .expect("P1_INNER should be 32 bytes");
    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let gen_inputs = vec![
        outer_hash_state_value.clone(),
        const_zero_value,
        const_one_value,
    ];
    let ot_send_inputs = vec![p1_inner_input.clone(), p2_inner_input.clone()];
    let ot_receive_inputs = vec![outer_hash_state_value];
    let cached_labels = vec![];

    let de_summary = follower
        .execute_skip_equality_check(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    let full_output_labels = de_summary.get_generator_summary().output_labels();
    let full_cwk = full_output_labels[0].clone().into_labels();
    let full_swk = full_output_labels[1].clone().into_labels();
    let full_civ = full_output_labels[2].clone().into_labels();
    let full_siv = full_output_labels[3].clone().into_labels();

    let active_output_labels = de_summary.get_evaluator_summary().output_labels();
    let active_cwk = active_output_labels[0].clone().into_labels();
    let active_swk = active_output_labels[1].clone().into_labels();
    let active_civ = active_output_labels[2].clone().into_labels();
    let active_siv = active_output_labels[3].clone().into_labels();

    Ok(SessionKeyLabels::new(
        full_cwk, full_swk, full_civ, full_siv, active_cwk, active_swk, active_civ, active_siv,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use hmac_sha256_core::{
        sha::{finalize_sha256_digest, partial_sha256_digest},
        utils::{compute_ms, hmac_sha256, key_expansion_tls12, seed_ke},
    };
    use mpc_aio::protocol::garble::exec::dual::mock::mock_dualex_pair;
    use mpc_circuits::BitOrder;
    use mpc_core::garble::exec::dual::DualExConfigBuilder;

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_session_keys() {
        let de_config = DualExConfigBuilder::default()
            .id("test".to_string())
            .circ(SESSION_KEYS.clone())
            .build()
            .expect("DE config should be valid");
        let (gc_leader, gc_follower) = mock_dualex_pair(de_config);

        let leader_encoder = Arc::new(Mutex::new(ChaChaEncoder::new([0u8; 32], BitOrder::Msb0)));
        let follower_encoder = Arc::new(Mutex::new(ChaChaEncoder::new([1u8; 32], BitOrder::Msb0)));

        let pms = [42u8; 32];
        let client_random = [69u8; 32];
        let server_random = [96u8; 32];
        let ms = compute_ms(&client_random, &server_random, &pms);

        let mut ms_zeropadded = [0u8; 64];
        ms_zeropadded[0..48].copy_from_slice(&ms);

        let ms_opad = ms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let ms_ipad = ms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        let ms_outer_hash_state = partial_sha256_digest(&ms_opad);
        let ms_inner_hash_state = partial_sha256_digest(&ms_ipad);

        let seed = seed_ke(&client_random, &server_random);
        let a1 = hmac_sha256(&ms, &seed);
        let a2 = hmac_sha256(&ms, &a1);
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed);

        let p1_inner_hash = finalize_sha256_digest(ms_inner_hash_state, 64, &a1_seed);
        let p2_inner_hash = finalize_sha256_digest(ms_inner_hash_state, 64, &a2_seed);

        let (expected_cwk, expected_swk, expected_civ, expected_siv) =
            key_expansion_tls12(&client_random, &server_random, &pms);

        let (leader_keys, follower_keys) = tokio::join!(
            async move {
                leader_session_keys(gc_leader, leader_encoder, 0, p1_inner_hash, p2_inner_hash)
                    .await
                    .unwrap()
            },
            async move {
                follower_session_keys(gc_follower, follower_encoder, 0, ms_outer_hash_state)
                    .await
                    .unwrap()
            }
        );

        let leader_cwk = leader_keys
            .active_cwk()
            .decode(follower_keys.full_cwk().get_decoding())
            .unwrap();
        let leader_swk = leader_keys
            .active_swk()
            .decode(follower_keys.full_swk().get_decoding())
            .unwrap();
        let leader_civ = leader_keys
            .active_civ()
            .decode(follower_keys.full_civ().get_decoding())
            .unwrap();
        let leader_siv = leader_keys
            .active_siv()
            .decode(follower_keys.full_siv().get_decoding())
            .unwrap();
        let follower_cwk = follower_keys
            .active_cwk()
            .decode(leader_keys.full_cwk().get_decoding())
            .unwrap();
        let follower_swk = follower_keys
            .active_swk()
            .decode(leader_keys.full_swk().get_decoding())
            .unwrap();
        let follower_civ = follower_keys
            .active_civ()
            .decode(leader_keys.full_civ().get_decoding())
            .unwrap();
        let follower_siv = follower_keys
            .active_siv()
            .decode(leader_keys.full_siv().get_decoding())
            .unwrap();

        assert_eq!(leader_cwk, follower_cwk);
        assert_eq!(leader_swk, follower_swk);
        assert_eq!(leader_civ, follower_civ);
        assert_eq!(leader_siv, follower_siv);

        let cwk = leader_cwk
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .rev()
            .collect::<Vec<u8>>();

        let swk = leader_swk
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .rev()
            .collect::<Vec<u8>>();

        let civ = leader_civ
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .rev()
            .collect::<Vec<u8>>();

        let siv = leader_siv
            .chunks_exact(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, b)| a | ((*b as u8) << i))
            })
            .rev()
            .collect::<Vec<u8>>();

        assert_eq!(cwk, expected_cwk);
        assert_eq!(swk, expected_swk);
        assert_eq!(civ, expected_civ);
        assert_eq!(siv, expected_siv);
    }
}
