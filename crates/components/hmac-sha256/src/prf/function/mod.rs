use crate::{sha256::Sha256, PrfError};
use mpz_circuits::circuits::xor;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};
use std::sync::Arc;

#[cfg(not(feature = "prf-local"))]
mod interactive;
#[cfg(not(feature = "prf-local"))]
pub(crate) use interactive::PrfFunction;

#[cfg(feature = "prf-local")]
mod local;
#[cfg(feature = "prf-local")]
pub(crate) use local::PrfFunction;

fn compute_partial(
    vm: &mut dyn Vm<Binary>,
    data: Vector<U8>,
    mask: [u8; 64],
) -> Result<Array<U32, 8>, PrfError> {
    let xor = Arc::new(xor(8 * 64));

    let additional_len = 64 - data.len();
    let padding = vec![0_u8; additional_len];

    let padding_ref: Vector<U8> = vm.alloc_vec(additional_len).map_err(PrfError::vm)?;
    vm.mark_public(padding_ref).map_err(PrfError::vm)?;
    vm.assign(padding_ref, padding).map_err(PrfError::vm)?;
    vm.commit(padding_ref).map_err(PrfError::vm)?;

    let mask_ref: Array<U8, 64> = vm.alloc().map_err(PrfError::vm)?;
    vm.mark_public(mask_ref).map_err(PrfError::vm)?;
    vm.assign(mask_ref, mask).map_err(PrfError::vm)?;
    vm.commit(mask_ref).map_err(PrfError::vm)?;

    let xor = Call::builder(xor)
        .arg(data)
        .arg(padding_ref)
        .arg(mask_ref)
        .build()
        .map_err(PrfError::vm)?;
    let key_padded = vm.call(xor).map_err(PrfError::vm)?;

    let mut sha = Sha256::new();
    sha.update(key_padded);
    sha.alloc(vm)
}

#[cfg(test)]
mod tests {
    use crate::{
        convert_to_bytes,
        prf::function::PrfFunction,
        test_utils::{mock_vm, phash},
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };

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

        let mut prf_leader =
            PrfFunction::alloc_master_secret(&mut leader, leader_key.into()).unwrap();
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

        let mut prf_follower =
            PrfFunction::alloc_master_secret(&mut follower, follower_key.into()).unwrap();
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
