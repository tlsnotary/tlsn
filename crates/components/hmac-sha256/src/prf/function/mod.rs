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
    Reduced(reduced::PrfFunction),
    Normal(normal::PrfFunction),
}

impl Prf {
    pub(crate) fn alloc_master_secret(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        let prf = match mode {
            Mode::Reduced => Self::Reduced(reduced::PrfFunction::alloc_master_secret(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Normal(normal::PrfFunction::alloc_master_secret(
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
            Mode::Reduced => Self::Reduced(reduced::PrfFunction::alloc_key_expansion(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Normal(normal::PrfFunction::alloc_key_expansion(
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
            Mode::Reduced => Self::Reduced(reduced::PrfFunction::alloc_client_finished(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Normal(normal::PrfFunction::alloc_client_finished(
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
            Mode::Reduced => Self::Reduced(reduced::PrfFunction::alloc_server_finished(
                vm,
                outer_partial,
                inner_partial,
            )?),
            Mode::Normal => Self::Normal(normal::PrfFunction::alloc_server_finished(
                vm,
                outer_partial,
                inner_partial,
            )?),
        };
        Ok(prf)
    }

    pub(crate) fn wants_flush(&mut self) -> bool {
        match self {
            Prf::Reduced(prf) => prf.wants_flush(),
            Prf::Normal(prf) => prf.wants_flush(),
        }
    }

    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        match self {
            Prf::Reduced(prf) => prf.flush(vm),
            Prf::Normal(prf) => prf.flush(vm),
        }
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        match self {
            Prf::Reduced(prf) => prf.set_start_seed(seed),
            Prf::Normal(prf) => prf.set_start_seed(seed),
        }
    }

    pub(crate) fn output(&self) -> Vec<Array<U32, 8>> {
        match self {
            Prf::Reduced(prf) => prf.output(),
            Prf::Normal(prf) => prf.output(),
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
    async fn test_phash_reduced() {
        let mode = Mode::Reduced;
        test_phash(mode).await;
    }

    #[tokio::test]
    async fn test_phash_normal() {
        let mode = Mode::Normal;
        test_phash(mode).await;
    }

    async fn test_phash(mode: Mode) {
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
            mode,
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
            mode,
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

        while prf_leader.wants_flush() || prf_follower.wants_flush() {
            tokio::try_join!(
                async {
                    prf_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await
                },
                async {
                    prf_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await
                }
            )
            .unwrap();
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
