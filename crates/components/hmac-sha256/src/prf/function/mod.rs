//! Provides [`Prf`], for computing the TLS 1.2 PRF.

use crate::{Mode, PrfError};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32},
        Array,
    },
    Vm,
};

mod normal;
mod reduced;

#[derive(Debug)]
pub(crate) enum Prf {
    Local(reduced::PrfFunction),
    Mpc(normal::PrfFunction),
}

impl Prf {
    pub(crate) fn alloc_master_secret(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        let prf = match mode {
            Mode::Reduced => Self::Local(reduced::PrfFunction::alloc_master_secret(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Mpc(normal::PrfFunction::alloc_master_secret(
                vm,
                outer_partial,
                inner_partial,
            )?),
        };
        Ok(prf)
    }

    pub(crate) fn alloc_key_expansion(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        let prf = match mode {
            Mode::Reduced => Self::Local(reduced::PrfFunction::alloc_key_expansion(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Mpc(normal::PrfFunction::alloc_key_expansion(
                vm,
                outer_partial,
                inner_partial,
            )?),
        };
        Ok(prf)
    }

    pub(crate) fn alloc_client_finished(
        config: Mode,
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        let prf = match config {
            Mode::Reduced => Self::Local(reduced::PrfFunction::alloc_client_finished(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Mpc(normal::PrfFunction::alloc_client_finished(
                vm,
                outer_partial,
                inner_partial,
            )?),
        };
        Ok(prf)
    }

    pub(crate) fn alloc_server_finished(
        config: Mode,
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        let prf = match config {
            Mode::Reduced => Self::Local(reduced::PrfFunction::alloc_server_finished(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Mpc(normal::PrfFunction::alloc_server_finished(
                vm,
                outer_partial,
                inner_partial,
            )?),
        };
        Ok(prf)
    }

    pub(crate) fn wants_flush(&self) -> bool {
        match self {
            Prf::Local(prf) => prf.wants_flush(),
            Prf::Mpc(prf) => prf.wants_flush(),
        }
    }

    pub(crate) fn make_progress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        match self {
            Prf::Local(prf) => prf.make_progress(vm),
            Prf::Mpc(prf) => prf.make_progress(vm),
        }
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        match self {
            Prf::Local(prf) => prf.set_start_seed(seed),
            Prf::Mpc(prf) => prf.set_start_seed(seed),
        }
    }

    pub(crate) fn output(&self) -> Vec<Array<U32, 8>> {
        match self {
            Prf::Local(prf) => prf.output(),
            Prf::Mpc(prf) => prf.output(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        convert_to_bytes,
        prf::{compute_partial, function::Prf},
        test_utils::{mock_vm, phash},
        Mode,
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };

    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    #[tokio::test]
    async fn test_phash_local() {
        let config = Mode::Reduced;
        test_phash(config).await;
    }

    #[tokio::test]
    async fn test_phash_mpc() {
        let config = Mode::Reduced;
        test_phash(config).await;
    }

    async fn test_phash(config: Mode) {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let start_seed: Vec<u8> = vec![42; 64];

        let mut label_seed = b"master secret".to_vec();
        label_seed.extend_from_slice(&start_seed);
        let iterations = 2;

        let leader_key: Array<U8, 32> = leader.alloc().unwrap();
        leader.mark_public(leader_key).unwrap();
        leader.assign(leader_key, key).unwrap();
        leader.commit(leader_key).unwrap();

        let outer_partial_leader = compute_partial(&mut leader, leader_key.into(), OPAD).unwrap();
        let inner_partial_leader = compute_partial(&mut leader, leader_key.into(), IPAD).unwrap();

        let mut prf_leader = Prf::alloc_master_secret(
            config,
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

        let mut prf_follower = Prf::alloc_master_secret(
            config,
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
