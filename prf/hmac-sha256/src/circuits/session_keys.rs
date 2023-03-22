use hmac_sha256_core::{MasterSecretStateLabels, SessionKeyLabels, SESSION_KEYS};
use mpc_garble::{exec::dual::DEExecute, GCError};
use mpc_garble_core::{ActiveEncodedInput, FullEncodedInput, FullInputSet};

/// Executes session_keys as PRFLeader
///
/// Returns session key shares
pub async fn session_keys<DE: DEExecute>(
    de: DE,
    ms_labels: MasterSecretStateLabels,
) -> Result<SessionKeyLabels, GCError> {
    let (gen_labels, cached_labels) = build_labels(ms_labels);
    let gen_inputs = vec![];
    let ot_send_inputs = vec![];
    let ot_receive_inputs = vec![];

    let de_summary = de
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

    Ok(SessionKeyLabels {
        full_cwk,
        full_swk,
        full_civ,
        full_siv,
        active_cwk,
        active_swk,
        active_civ,
        active_siv,
    })
}

fn build_labels(ms_labels: MasterSecretStateLabels) -> (FullInputSet, Vec<ActiveEncodedInput>) {
    let [outer_hash_state_input, inner_hash_state_input, client_random_input, server_random_input, const_zero, const_one] = SESSION_KEYS.inputs() else {
        panic!("session_keys circuit should have 6 inputs");
    };

    let full_outer_hash_state = FullEncodedInput::from_labels(
        outer_hash_state_input.clone(),
        ms_labels.full_outer_hash_state,
    )
    .expect("outer_hash_state should be valid");

    let full_inner_hash_state = FullEncodedInput::from_labels(
        inner_hash_state_input.clone(),
        ms_labels.full_inner_hash_state,
    )
    .expect("inner_hash_state should be valid");

    let full_client_random =
        FullEncodedInput::from_labels(client_random_input.clone(), ms_labels.full_client_random)
            .expect("client_random should be valid");

    let full_server_random =
        FullEncodedInput::from_labels(server_random_input.clone(), ms_labels.full_server_random)
            .expect("server_random should be valid");

    let full_const_zero =
        FullEncodedInput::from_labels(const_zero.clone(), ms_labels.full_const_zero)
            .expect("const_zero should be valid");

    let full_const_one = FullEncodedInput::from_labels(const_one.clone(), ms_labels.full_const_one)
        .expect("const_one should be valid");

    let gen_labels = FullInputSet::new(vec![
        full_outer_hash_state,
        full_inner_hash_state,
        full_client_random,
        full_server_random,
        full_const_zero,
        full_const_one,
    ])
    .expect("Labels should be valid");

    let active_outer_hash_state = ActiveEncodedInput::from_active_labels(
        outer_hash_state_input.clone(),
        ms_labels.active_outer_hash_state,
    )
    .expect("outer_hash_state should be valid");

    let active_inner_hash_state = ActiveEncodedInput::from_active_labels(
        inner_hash_state_input.clone(),
        ms_labels.active_inner_hash_state,
    )
    .expect("inner_hash_state should be valid");

    let active_client_random = ActiveEncodedInput::from_active_labels(
        client_random_input.clone(),
        ms_labels.active_client_random,
    )
    .expect("client_random should be valid");

    let active_server_random = ActiveEncodedInput::from_active_labels(
        server_random_input.clone(),
        ms_labels.active_server_random,
    )
    .expect("server_random should be valid");

    let active_const_zero =
        ActiveEncodedInput::from_active_labels(const_zero.clone(), ms_labels.active_const_zero)
            .expect("const_zero should be valid");

    let active_const_one =
        ActiveEncodedInput::from_active_labels(const_one.clone(), ms_labels.active_const_one)
            .expect("const_one should be valid");

    let cached_labels = vec![
        active_outer_hash_state,
        active_inner_hash_state,
        active_client_random,
        active_server_random,
        active_const_zero,
        active_const_one,
    ];

    (gen_labels, cached_labels)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hmac_sha256_core::mock::create_mock_ms_state_labels;
    use mpc_garble::exec::dual::mock::mock_dualex_pair;
    use mpc_garble_core::exec::dual::DualExConfigBuilder;
    use utils::bits::FromBits;

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_session_keys() {
        let de_config = DualExConfigBuilder::default()
            .id("test".to_string())
            .circ(SESSION_KEYS.clone())
            .build()
            .expect("DE config should be valid");
        let (gc_leader, gc_follower) = mock_dualex_pair(de_config);

        let ms = [42u8; 48];
        let client_random = [69u8; 32];
        let server_random = [96u8; 32];

        let ((leader_labels, follower_labels), _) =
            create_mock_ms_state_labels(ms, client_random, server_random);

        let (leader_keys, follower_keys) = tokio::try_join!(
            session_keys(gc_leader, leader_labels),
            session_keys(gc_follower, follower_labels)
        )
        .unwrap();

        let (
            leader_cwk,
            leader_swk,
            leader_civ,
            leader_siv,
            follower_cwk,
            follower_swk,
            follower_civ,
            follower_siv,
        ) = decode_keys(leader_keys, follower_keys);

        assert_eq!(leader_cwk, follower_cwk);
        assert_eq!(leader_swk, follower_swk);
        assert_eq!(leader_civ, follower_civ);
        assert_eq!(leader_siv, follower_siv);

        let seed = server_random
            .iter()
            .chain(client_random.iter())
            .copied()
            .collect::<Vec<_>>();
        let expected_key_material = hmac_sha256_utils::prf(&ms, b"key expansion", &seed, 40);

        let expected_cwk = expected_key_material[0..16].to_vec();
        let expected_swk = expected_key_material[16..32].to_vec();
        let expected_civ = expected_key_material[32..36].to_vec();
        let expected_siv = expected_key_material[36..40].to_vec();

        assert_eq!(leader_cwk, expected_cwk);
        assert_eq!(leader_swk, expected_swk);
        assert_eq!(leader_civ, expected_civ);
        assert_eq!(leader_siv, expected_siv);
    }

    fn decode_keys(
        leader_keys: SessionKeyLabels,
        follower_keys: SessionKeyLabels,
    ) -> (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) {
        let leader_cwk = Vec::<u8>::from_msb0(
            leader_keys
                .active_cwk
                .decode(follower_keys.full_cwk.get_decoding())
                .unwrap(),
        );
        let leader_swk = Vec::<u8>::from_msb0(
            leader_keys
                .active_swk
                .decode(follower_keys.full_swk.get_decoding())
                .unwrap(),
        );
        let leader_civ = Vec::<u8>::from_msb0(
            leader_keys
                .active_civ
                .decode(follower_keys.full_civ.get_decoding())
                .unwrap(),
        );
        let leader_siv = Vec::<u8>::from_msb0(
            leader_keys
                .active_siv
                .decode(follower_keys.full_siv.get_decoding())
                .unwrap(),
        );
        let follower_cwk = Vec::<u8>::from_msb0(
            follower_keys
                .active_cwk
                .decode(leader_keys.full_cwk.get_decoding())
                .unwrap(),
        );
        let follower_swk = Vec::<u8>::from_msb0(
            follower_keys
                .active_swk
                .decode(leader_keys.full_swk.get_decoding())
                .unwrap(),
        );
        let follower_civ = Vec::<u8>::from_msb0(
            follower_keys
                .active_civ
                .decode(leader_keys.full_civ.get_decoding())
                .unwrap(),
        );
        let follower_siv = Vec::<u8>::from_msb0(
            follower_keys
                .active_siv
                .decode(leader_keys.full_siv.get_decoding())
                .unwrap(),
        );

        (
            leader_cwk,
            leader_swk,
            leader_civ,
            leader_siv,
            follower_cwk,
            follower_swk,
            follower_civ,
            follower_siv,
        )
    }
}
