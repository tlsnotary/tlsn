use mpc_circuits::{BitOrder, Value};
use mpc_core::garble::{ChaChaEncoder, Encoder};

use super::*;

pub fn create_mock_pms_labels(
    pms: [u8; 32],
) -> ((PmsLabels, PmsLabels), (ChaChaEncoder, ChaChaEncoder)) {
    let mut leader_encoder = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);
    let mut follower_encoder = ChaChaEncoder::new([1u8; 32], BitOrder::Msb0);

    let pms = pms.to_vec();

    let leader_delta = leader_encoder.get_delta();
    let follower_delta = follower_encoder.get_delta();

    let leader_rng = leader_encoder.get_stream(0);
    let follower_rng = follower_encoder.get_stream(0);

    let leader_full_labels = FullLabels::generate(leader_rng, 256, Some(leader_delta));
    let follower_full_labels = FullLabels::generate(follower_rng, 256, Some(follower_delta));

    let leader_active_labels = leader_full_labels
        .select(&pms.clone().into(), BitOrder::Msb0)
        .unwrap();
    let follower_active_labels = follower_full_labels
        .select(&pms.into(), BitOrder::Msb0)
        .unwrap();

    let leader_pms_labels = PmsLabels {
        full: leader_full_labels,
        active: follower_active_labels,
    };

    let follower_pms_labels = PmsLabels {
        full: follower_full_labels,
        active: leader_active_labels,
    };

    (
        (leader_pms_labels, follower_pms_labels),
        (leader_encoder, follower_encoder),
    )
}

pub fn create_mock_ms_state_labels(
    ms: [u8; 48],
    client_random: [u8; 32],
    server_random: [u8; 32],
) -> (
    (MasterSecretStateLabels, MasterSecretStateLabels),
    (ChaChaEncoder, ChaChaEncoder),
) {
    let mut leader_encoder = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);
    let mut follower_encoder = ChaChaEncoder::new([1u8; 32], BitOrder::Msb0);

    let (outer_hash_state, inner_hash_state) = hmac_sha256_utils::partial_hmac(&ms);

    let outer_hash_state = outer_hash_state
        .iter()
        .map(|chunk| chunk.to_be_bytes())
        .flatten()
        .collect::<Vec<u8>>();
    let inner_hash_state = inner_hash_state
        .iter()
        .map(|chunk| chunk.to_be_bytes())
        .flatten()
        .collect::<Vec<u8>>();

    let leader_delta = leader_encoder.get_delta();
    let follower_delta = follower_encoder.get_delta();

    let leader_rng = leader_encoder.get_stream(0);
    let follower_rng = follower_encoder.get_stream(0);

    let leader_full_outer_hash_state = FullLabels::generate(leader_rng, 256, Some(leader_delta));
    let leader_full_inner_hash_state = FullLabels::generate(leader_rng, 256, Some(leader_delta));
    let leader_full_client_random = FullLabels::generate(leader_rng, 256, Some(leader_delta));
    let leader_full_server_random = FullLabels::generate(leader_rng, 256, Some(leader_delta));
    let leader_full_const_zero = FullLabels::generate(leader_rng, 1, Some(leader_delta));
    let leader_full_const_one = FullLabels::generate(leader_rng, 1, Some(leader_delta));

    let follower_full_outer_hash_state =
        FullLabels::generate(follower_rng, 256, Some(follower_delta));
    let follower_full_inner_hash_state =
        FullLabels::generate(follower_rng, 256, Some(follower_delta));
    let follower_full_client_random = FullLabels::generate(follower_rng, 256, Some(follower_delta));
    let follower_full_server_random = FullLabels::generate(follower_rng, 256, Some(follower_delta));
    let follower_full_const_zero = FullLabels::generate(follower_rng, 1, Some(follower_delta));
    let follower_full_const_one = FullLabels::generate(follower_rng, 1, Some(follower_delta));

    let leader_active_outer_hash_state = follower_full_outer_hash_state
        .select(&outer_hash_state.clone().into(), BitOrder::Msb0)
        .unwrap();
    let leader_active_inner_hash_state = follower_full_inner_hash_state
        .select(&inner_hash_state.clone().into(), BitOrder::Msb0)
        .unwrap();
    let leader_active_client_random = follower_full_client_random
        .select(&client_random.to_vec().into(), BitOrder::Msb0)
        .unwrap();
    let leader_active_server_random = follower_full_server_random
        .select(&server_random.to_vec().into(), BitOrder::Msb0)
        .unwrap();
    let leader_active_const_zero = follower_full_const_zero
        .select(&Value::ConstZero, BitOrder::Msb0)
        .unwrap();
    let leader_active_const_one = follower_full_const_one
        .select(&Value::ConstOne, BitOrder::Msb0)
        .unwrap();

    let follower_active_outer_hash_state = leader_full_outer_hash_state
        .select(&outer_hash_state.into(), BitOrder::Msb0)
        .unwrap();
    let follower_active_inner_hash_state = leader_full_inner_hash_state
        .select(&inner_hash_state.into(), BitOrder::Msb0)
        .unwrap();
    let follower_active_client_random = leader_full_client_random
        .select(&client_random.to_vec().into(), BitOrder::Msb0)
        .unwrap();
    let follower_active_server_random = leader_full_server_random
        .select(&server_random.to_vec().into(), BitOrder::Msb0)
        .unwrap();
    let follower_active_const_zero = leader_full_const_zero
        .select(&Value::ConstZero, BitOrder::Msb0)
        .unwrap();
    let follower_active_const_one = leader_full_const_one
        .select(&Value::ConstOne, BitOrder::Msb0)
        .unwrap();

    let leader_ms_state_labels = MasterSecretStateLabels {
        full_outer_hash_state: leader_full_outer_hash_state,
        full_inner_hash_state: leader_full_inner_hash_state,
        active_outer_hash_state: leader_active_outer_hash_state,
        active_inner_hash_state: leader_active_inner_hash_state,
        full_client_random: leader_full_client_random,
        full_server_random: leader_full_server_random,
        active_client_random: leader_active_client_random,
        active_server_random: leader_active_server_random,
        full_const_zero: leader_full_const_zero,
        active_const_zero: leader_active_const_zero,
        full_const_one: leader_full_const_one,
        active_const_one: leader_active_const_one,
    };

    let follower_ms_state_labels = MasterSecretStateLabels {
        full_outer_hash_state: follower_full_outer_hash_state,
        full_inner_hash_state: follower_full_inner_hash_state,
        active_outer_hash_state: follower_active_outer_hash_state,
        active_inner_hash_state: follower_active_inner_hash_state,
        full_client_random: follower_full_client_random,
        full_server_random: follower_full_server_random,
        active_client_random: follower_active_client_random,
        active_server_random: follower_active_server_random,
        full_const_zero: follower_full_const_zero,
        active_const_zero: follower_active_const_zero,
        full_const_one: follower_full_const_one,
        active_const_one: follower_active_const_one,
    };

    (
        (leader_ms_state_labels, follower_ms_state_labels),
        (leader_encoder, follower_encoder),
    )
}
