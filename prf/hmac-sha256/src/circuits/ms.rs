use hmac_sha256_core::{MasterSecretStateLabels, MS};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, GCError};
use mpc_circuits::{Value, WireGroup};
use mpc_core::garble::FullInputSet;
use rand::{thread_rng, Rng};

/// Executes master secret circuit as PRFLeader
///
/// Returns inner_hash_state
pub async fn leader_ms<DE: DEExecute>(
    leader: DE,
    p1_inner_hash: [u8; 32],
) -> Result<([u32; 8], MasterSecretStateLabels), GCError> {
    let circ = MS.clone();

    let [outer_hash_state_input, p1_inner, p2, mask_outer, mask_inner, const_zero, const_one] = circ.inputs() else {
        panic!("Circuit 2 should have 5 inputs");
    };

    let gen_labels = FullInputSet::generate(&mut thread_rng(), &circ, None);

    let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
    let mask_inner_value = mask_inner
        .clone()
        .to_value(mask.clone())
        .expect("MASK_I should be 32 bytes");
    let p1_inner_value = p1_inner
        .clone()
        .to_value(p1_inner_hash.to_vec())
        .expect("P1_INNER should be 32 bytes");
    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let (_, summary) = leader
        .execute_and_summarize(
            gen_labels,
            vec![
                p1_inner_value.clone(),
                mask_inner_value.clone(),
                const_zero_value,
                const_one_value,
            ],
            vec![
                outer_hash_state_input.clone(),
                p2.clone(),
                mask_outer.clone(),
            ],
            vec![mask_inner_value, p1_inner_value],
            vec![],
        )
        .await?;

    let full_input_labels = summary.get_generator_summary().input_labels();
    let full_output_labels = summary.get_generator_summary().output_labels();
    let full_mask_outer_labels = full_input_labels[3].clone().into_labels();
    let full_mask_inner_labels = full_input_labels[4].clone().into_labels();
    let full_masked_outer_hash_state = full_output_labels[0].clone().into_labels();
    let full_masked_inner_hash_state = full_output_labels[1].clone().into_labels();

    // Compute labels for outer hash state by removing masks
    let full_outer_hash_state_labels = full_mask_outer_labels ^ full_masked_outer_hash_state;
    let full_inner_hash_state_labels = full_mask_inner_labels ^ full_masked_inner_hash_state;

    let active_input_labels = summary.get_evaluator_summary().input_labels();
    let active_output_labels = summary.get_evaluator_summary().output_labels();
    let active_mask_outer_labels = active_input_labels[3].clone().into_labels();
    let active_mask_inner_labels = active_input_labels[4].clone().into_labels();
    let active_masked_outer_hash_state = active_output_labels[0].clone().into_labels();
    let active_masked_inner_hash_state = active_output_labels[1].clone().into_labels();

    // Compute labels for outer hash state by removing masks
    let active_outer_hash_state_labels = active_mask_outer_labels ^ active_masked_outer_hash_state;
    let active_inner_hash_state_labels = active_mask_inner_labels ^ active_masked_inner_hash_state;

    let labels = MasterSecretStateLabels::new(
        full_outer_hash_state_labels,
        full_inner_hash_state_labels,
        active_outer_hash_state_labels,
        active_inner_hash_state_labels,
    );

    let outputs = summary.get_evaluator_summary().decode()?;

    let Value::Bytes(masked_inner_hash_state) = outputs[1].value().clone() else {
        panic!("MS circuit output 1 should be bytes");
    };

    // Remove mask
    let inner_hash_state = masked_inner_hash_state
        .iter()
        .zip(mask.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let inner_hash_state = inner_hash_state
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().expect("chunk should be 4 bytes")))
        .collect::<Vec<u32>>()
        .try_into()
        .expect("inner hash state should be 32 bytes");

    Ok((inner_hash_state, labels))
}

/// Executes master secret circuit as PRFFollower
///
/// Returns outer_hash_state
pub async fn follower_ms<DE: DEExecute>(
    follower: DE,
    pms_outer_hash_state: [u32; 8],
    p2: [u8; 32],
) -> Result<([u32; 8], MasterSecretStateLabels), GCError> {
    let circ = MS.clone();

    let [outer_hash_state_input, p1_inner, p2_input, mask_outer, mask_inner, const_zero, const_one] = circ.inputs() else {
        panic!("Circuit 2 should have 5 inputs");
    };

    let gen_labels = FullInputSet::generate(&mut thread_rng(), &circ, None);

    let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
    let mask_outer_value = mask_outer
        .clone()
        .to_value(mask.clone())
        .expect("MASK_O should be 32 bytes");
    let outer_hash_state_value = outer_hash_state_input
        .clone()
        .to_value(
            pms_outer_hash_state
                .into_iter()
                .map(|chunk| chunk.to_be_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        )
        .expect("outer_hash_state should be 32 bytes");
    let p2_value = p2_input
        .clone()
        .to_value(p2[..16].to_vec())
        .expect("P2 should be 32 bytes");
    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let (_, summary) = follower
        .execute_and_summarize(
            gen_labels,
            vec![
                outer_hash_state_value.clone(),
                p2_value.clone(),
                mask_outer_value.clone(),
                const_zero_value,
                const_one_value,
            ],
            vec![mask_inner.clone(), p1_inner.clone()],
            vec![outer_hash_state_value, p2_value, mask_outer_value],
            vec![],
        )
        .await?;

    let full_input_labels = summary.get_generator_summary().input_labels();
    let full_output_labels = summary.get_generator_summary().output_labels();
    let full_mask_outer_labels = full_input_labels[3].clone().into_labels();
    let full_mask_inner_labels = full_input_labels[4].clone().into_labels();
    let full_masked_outer_hash_state = full_output_labels[0].clone().into_labels();
    let full_masked_inner_hash_state = full_output_labels[1].clone().into_labels();

    // Compute labels for hash states by removing masks
    let full_outer_hash_state_labels = full_mask_outer_labels ^ full_masked_outer_hash_state;
    let full_inner_hash_state_labels = full_mask_inner_labels ^ full_masked_inner_hash_state;

    let active_input_labels = summary.get_evaluator_summary().input_labels();
    let active_output_labels = summary.get_evaluator_summary().output_labels();
    let active_mask_outer_labels = active_input_labels[3].clone().into_labels();
    let active_mask_inner_labels = active_input_labels[4].clone().into_labels();
    let active_masked_outer_hash_state = active_output_labels[0].clone().into_labels();
    let active_masked_inner_hash_state = active_output_labels[1].clone().into_labels();

    // Compute labels for hash states by removing masks
    let active_outer_hash_state_labels = active_mask_outer_labels ^ active_masked_outer_hash_state;
    let active_inner_hash_state_labels = active_mask_inner_labels ^ active_masked_inner_hash_state;

    let labels = MasterSecretStateLabels::new(
        full_outer_hash_state_labels,
        full_inner_hash_state_labels,
        active_outer_hash_state_labels,
        active_inner_hash_state_labels,
    );

    let outputs = summary.get_evaluator_summary().decode()?;

    let Value::Bytes(masked_outer_hash_state) = outputs[0].value().clone() else {
        panic!("MS circuit output 0 should be bytes");
    };

    // Remove mask
    let outer_hash_state = masked_outer_hash_state
        .iter()
        .zip(mask.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let outer_hash_state = outer_hash_state
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().expect("chunk should be 4 bytes")))
        .collect::<Vec<u32>>()
        .try_into()
        .expect("outer hash state should be 32 bytes");

    Ok((outer_hash_state, labels))
}

#[cfg(test)]
mod tests {
    use super::*;

    use hmac_sha256_core::{
        sha::{finalize_sha256_digest, partial_sha256_digest},
        utils::{compute_ms, hmac_sha256, seed_ms},
    };
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
        let ms = compute_ms(&client_random, &server_random, &pms);

        let mut ms_zeropadded = [0u8; 64];
        ms_zeropadded[0..48].copy_from_slice(&ms);

        let ms_opad = ms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let ms_ipad = ms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        let expected_ms_outer_hash_state = partial_sha256_digest(&ms_opad);
        let expected_ms_inner_hash_state = partial_sha256_digest(&ms_ipad);

        let mut pms_padded = [0u8; 64];
        pms_padded[0..32].copy_from_slice(&pms);

        let pms_opad = pms_padded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let pms_ipad = pms_padded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();

        let pms_outer_hash_state = partial_sha256_digest(&pms_opad);
        let pms_inner_hash_state = partial_sha256_digest(&pms_ipad);

        let seed = seed_ms(&client_random, &server_random);
        let a1 = hmac_sha256(&pms, &seed);
        let a2 = hmac_sha256(&pms, &a1);
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed);
        let p1_inner_hash = finalize_sha256_digest(pms_inner_hash_state, 64, &a1_seed);
        let p2 = hmac_sha256(&pms, &a2_seed);

        let ((ms_inner_hash_state, _), (ms_outer_hash_state, _)) = futures::join!(
            async move { leader_ms(gc_leader, p1_inner_hash).await.unwrap() },
            async move {
                follower_ms(gc_follower, pms_outer_hash_state, p2)
                    .await
                    .unwrap()
            }
        );

        assert_eq!(ms_outer_hash_state, expected_ms_outer_hash_state);
        assert_eq!(ms_inner_hash_state, expected_ms_inner_hash_state);
    }
}
