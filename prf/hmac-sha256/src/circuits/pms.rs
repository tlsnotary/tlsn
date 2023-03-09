use hmac_sha256_core::{PmsLabels, Role, PMS};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, GCError};
use mpc_circuits::{Value, WireGroup};
use mpc_core::garble::{ActiveEncodedInput, FullEncodedInput, FullInputSet};
use rand::{thread_rng, Rng};

/// Executes pms circuit
///
/// Returns hash state share
pub async fn execute_pms<DE: DEExecute>(
    de: DE,
    role: Role,
    labels: PmsLabels,
) -> Result<[u32; 8], GCError> {
    let circ = PMS.clone();
    let delta = labels.full_labels().get_delta();

    let [pms,  mask_outer, mask_inner, const_zero, const_one] = circ.inputs() else {
        panic!("PMS circuit should have 5 inputs");
    };

    let pms_labels = FullEncodedInput::from_labels(pms.clone(), labels.full_labels().clone())
        .expect("PMS labels should be valid");
    let mask_inner_labels =
        FullEncodedInput::generate(&mut thread_rng(), mask_inner.clone(), delta);
    let mask_outer_labels =
        FullEncodedInput::generate(&mut thread_rng(), mask_outer.clone(), delta);
    let const_zero_labels =
        FullEncodedInput::generate(&mut thread_rng(), const_zero.clone(), delta);
    let const_one_labels = FullEncodedInput::generate(&mut thread_rng(), const_one.clone(), delta);

    let gen_labels = FullInputSet::new(vec![
        pms_labels,
        mask_inner_labels,
        mask_outer_labels,
        const_zero_labels,
        const_one_labels,
    ])
    .expect("All labels should be valid");

    let active_pms =
        ActiveEncodedInput::from_active_labels(pms.clone(), labels.active_labels().clone())
            .expect("PMS labels should be valid");

    let const_zero_value = const_zero
        .clone()
        .to_value(Value::ConstZero)
        .expect("const_zero should be 0");
    let const_one_value = const_one
        .clone()
        .to_value(Value::ConstOne)
        .expect("const_one should be 1");

    let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
    let (gen_inputs, ot_send_inputs, ot_receive_inputs) = match role {
        Role::Leader => {
            let mask_inner_value = mask_inner
                .clone()
                .to_value(mask.clone())
                .expect("MASK_I should be 32 bytes");

            let gen_inputs = vec![mask_inner_value.clone(), const_zero_value, const_one_value];
            let ot_send_inputs = vec![mask_outer.clone()];
            let ot_receive_inputs = vec![mask_inner_value];

            (gen_inputs, ot_send_inputs, ot_receive_inputs)
        }
        Role::Follower => {
            let mask_outer_value = mask_outer
                .clone()
                .to_value(mask.clone())
                .expect("MASK_O should be 32 bytes");

            let gen_inputs = vec![mask_outer_value.clone(), const_zero_value, const_one_value];
            let ot_send_inputs = vec![mask_inner.clone()];
            let ot_receive_inputs = vec![mask_outer_value];

            (gen_inputs, ot_send_inputs, ot_receive_inputs)
        }
    };

    let output = de
        .execute(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            vec![active_pms],
        )
        .await?;

    let masked_hash_state = match role {
        Role::Leader => output[1].value().clone(),
        Role::Follower => output[0].value().clone(),
    };

    let Value::Bytes(masked_hash_state) = masked_hash_state else {
        panic!("Masked hash state should be bytes");
    };

    // Remove mask
    let hash_state = masked_hash_state
        .iter()
        .zip(mask.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let hash_state = hash_state
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().expect("chunk should be 4 bytes")))
        .collect::<Vec<u32>>()
        .try_into()
        .expect("inner hash state should be 32 bytes");

    Ok(hash_state)
}

#[cfg(test)]
mod tests {
    use crate::mock::create_mock_pms_labels;
    use hmac_sha256_core::sha::partial_sha256_digest;
    use mpc_aio::protocol::garble::exec::dual::mock::mock_dualex_pair;
    use mpc_core::garble::exec::dual::DualExConfigBuilder;

    use super::*;

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_pms() {
        let de_config = DualExConfigBuilder::default()
            .id("test".to_string())
            .circ(PMS.clone())
            .build()
            .expect("DE config should be valid");
        let (gc_leader, gc_follower) = mock_dualex_pair(de_config);

        let pms = [42u8; 32];

        let ((leader_labels, follower_labels), _) = create_mock_pms_labels(pms);

        let mut pms_zeropadded = [0u8; 64];
        pms_zeropadded[..32].copy_from_slice(&pms);
        let pms_opad = pms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let pms_ipad = pms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();
        let expected_outer_hash_state = partial_sha256_digest(&pms_opad);
        let expected_inner_hash_state = partial_sha256_digest(&pms_ipad);

        let (inner_hash_state, outer_hash_state) = tokio::join!(
            async move {
                execute_pms(gc_leader, Role::Leader, leader_labels)
                    .await
                    .unwrap()
            },
            async move {
                execute_pms(gc_follower, Role::Follower, follower_labels)
                    .await
                    .unwrap()
            }
        );

        assert_eq!(outer_hash_state, expected_outer_hash_state);
        assert_eq!(inner_hash_state, expected_inner_hash_state);
    }
}
