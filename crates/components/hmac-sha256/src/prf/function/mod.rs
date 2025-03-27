//! Provides [`PrfFunction`], for computing the TLS 1.2 PRF.
//!
//! If the feature flag `local-hash` is set, provides an implementation
//! which computes some hashes locally.

#[cfg(not(feature = "local-hash"))]
mod interactive;
#[cfg(not(feature = "local-hash"))]
pub(crate) use interactive::PrfFunction;

#[cfg(feature = "local-hash")]
mod local;
#[cfg(feature = "local-hash")]
pub(crate) use local::PrfFunction;

#[cfg(test)]
mod tests {
    use crate::{
        convert_to_bytes,
        prf::{compute_partial, function::PrfFunction},
        test_utils::{mock_vm, phash},
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };

    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    #[tokio::test]
    async fn test_phash() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let start_seed: Vec<u8> = vec![42; 64];

        let mut label_seed = PrfFunction::MS_LABEL.to_vec();
        label_seed.extend_from_slice(&start_seed);
        let iterations = 2;

        let leader_key: Array<U8, 32> = leader.alloc().unwrap();
        leader.mark_public(leader_key).unwrap();
        leader.assign(leader_key, key).unwrap();
        leader.commit(leader_key).unwrap();

        let outer_partial_leader = compute_partial(&mut leader, leader_key.into(), OPAD).unwrap();
        let inner_partial_leader = compute_partial(&mut leader, leader_key.into(), IPAD).unwrap();

        let mut prf_leader = PrfFunction::alloc_master_secret(
            &mut leader,
            outer_partial_leader,
            inner_partial_leader,
        )
        .unwrap();
        prf_leader.set_start_seed(start_seed.clone());

        let mut prf_out_leader = vec![];
        for p in prf_leader.output() {
            let p_out = leader.decode(p).unwrap();
            prf_out_leader.push(p_out)
        }

        let follower_key: Array<U8, 32> = follower.alloc().unwrap();
        follower.mark_public(follower_key).unwrap();
        follower.assign(follower_key, key).unwrap();
        follower.commit(follower_key).unwrap();

        let outer_partial_follower =
            compute_partial(&mut follower, follower_key.into(), OPAD).unwrap();
        let inner_partial_follower =
            compute_partial(&mut follower, follower_key.into(), IPAD).unwrap();

        let mut prf_follower = PrfFunction::alloc_master_secret(
            &mut follower,
            outer_partial_follower,
            inner_partial_follower,
        )
        .unwrap();
        prf_follower.set_start_seed(start_seed.clone());

        let mut prf_out_follower = vec![];
        for p in prf_follower.output() {
            let p_out = follower.decode(p).unwrap();
            prf_out_follower.push(p_out)
        }

        loop {
            let leader_finished = prf_leader.make_progress(&mut leader).unwrap();
            let follower_finished = prf_follower.make_progress(&mut follower).unwrap();

            tokio::try_join!(
                leader.execute_all(&mut ctx_a),
                follower.execute_all(&mut ctx_b)
            )
            .unwrap();

            if leader_finished && follower_finished {
                break;
            }
        }

        assert_eq!(prf_out_leader.len(), prf_out_follower.len());

        let prf_result_leader: Vec<u8> = prf_out_leader
            .iter_mut()
            .flat_map(|p| convert_to_bytes(p.try_recv().unwrap().unwrap()))
            .collect();
        let prf_result_follower: Vec<u8> = prf_out_follower
            .iter_mut()
            .flat_map(|p| convert_to_bytes(p.try_recv().unwrap().unwrap()))
            .collect();

        let expected = phash(key.to_vec(), &label_seed, iterations);

        assert_eq!(prf_result_leader, prf_result_follower);
        assert_eq!(prf_result_leader, expected)
    }
}
