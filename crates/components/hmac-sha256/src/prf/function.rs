//! Provides [`Prf`], for computing the TLS 1.2 PRF.

use crate::{hmac::Hmac, FError, Mode};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Vector,
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
    /// Allocates master secret.
    pub(crate) fn alloc_master_secret(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        hmac: Hmac,
    ) -> Result<Self, FError> {
        let prf = match mode {
            Mode::Reduced => {
                if let Hmac::Reduced(hmac) = hmac {
                    Self::Reduced(reduced::PrfFunction::alloc_master_secret(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
            Mode::Normal => {
                if let Hmac::Normal(hmac) = hmac {
                    Self::Normal(normal::PrfFunction::alloc_master_secret(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
        };
        Ok(prf)
    }

    /// Allocates key expansion.
    pub(crate) fn alloc_key_expansion(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        hmac: Hmac,
    ) -> Result<Self, FError> {
        let prf = match mode {
            Mode::Reduced => {
                if let Hmac::Reduced(hmac) = hmac {
                    Self::Reduced(reduced::PrfFunction::alloc_key_expansion(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
            Mode::Normal => {
                if let Hmac::Normal(hmac) = hmac {
                    Self::Normal(normal::PrfFunction::alloc_key_expansion(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
        };
        Ok(prf)
    }

    /// Allocates client finished.
    pub(crate) fn alloc_client_finished(
        config: Mode,
        vm: &mut dyn Vm<Binary>,
        hmac: Hmac,
    ) -> Result<Self, FError> {
        let prf = match config {
            Mode::Reduced => {
                if let Hmac::Reduced(hmac) = hmac {
                    Self::Reduced(reduced::PrfFunction::alloc_client_finished(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
            Mode::Normal => {
                if let Hmac::Normal(hmac) = hmac {
                    Self::Normal(normal::PrfFunction::alloc_client_finished(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
        };
        Ok(prf)
    }

    /// Allocates server finished.
    pub(crate) fn alloc_server_finished(
        config: Mode,
        vm: &mut dyn Vm<Binary>,
        hmac: Hmac,
    ) -> Result<Self, FError> {
        let prf = match config {
            Mode::Reduced => {
                if let Hmac::Reduced(hmac) = hmac {
                    Self::Reduced(reduced::PrfFunction::alloc_server_finished(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
            Mode::Normal => {
                if let Hmac::Normal(hmac) = hmac {
                    Self::Normal(normal::PrfFunction::alloc_server_finished(vm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
        };
        Ok(prf)
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        match self {
            Prf::Reduced(prf) => prf.wants_flush(),
            Prf::Normal(prf) => prf.wants_flush(),
        }
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        match self {
            Prf::Reduced(prf) => prf.flush(vm),
            Prf::Normal(prf) => prf.flush(vm),
        }
    }

    /// Sets the seed.
    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        match self {
            Prf::Reduced(prf) => prf.set_start_seed(seed),
            Prf::Normal(prf) => prf.set_start_seed(seed),
        }
    }

    /// Returns the PRF output.
    pub(crate) fn output(&self) -> Vector<U8> {
        match self {
            Prf::Reduced(prf) => prf.output(),
            Prf::Normal(prf) => prf.output(),
        }
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        match self {
            Prf::Reduced(prf) => prf.is_complete(),
            Prf::Normal(prf) => prf.is_complete(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        hmac::Hmac,
        prf::function::Prf,
        test_utils::{mock_vm, phash},
        Mode,
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };
    use rand::{rngs::ThreadRng, Rng};
    use rstest::*;

    #[rstest]
    #[case::normal(Mode::Normal)]
    #[case::reduced(Mode::Reduced)]
    #[tokio::test]
    async fn test_phash(#[case] mode: Mode) {
        let mut rng = ThreadRng::default();

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let key: [u8; 32] = rng.random();
        let start_seed: Vec<u8> = vec![42; 64];
        let output_len = 48;

        let mut label_seed = b"master secret".to_vec();
        label_seed.extend_from_slice(&start_seed);
        let iterations = 2;

        let leader_key: Array<U8, 32> = leader.alloc().unwrap();
        leader.mark_public(leader_key).unwrap();
        leader.assign(leader_key, key).unwrap();
        leader.commit(leader_key).unwrap();

        let leader_hmac = Hmac::alloc(&mut leader, leader_key.into(), mode).unwrap();

        let mut prf_leader = Prf::alloc_master_secret(mode, &mut leader, leader_hmac).unwrap();
        prf_leader.set_start_seed(start_seed.clone());

        let mut prf_out_leader = leader.decode(prf_leader.output()).unwrap();

        let follower_key: Array<U8, 32> = follower.alloc().unwrap();
        follower.mark_public(follower_key).unwrap();
        follower.assign(follower_key, key).unwrap();
        follower.commit(follower_key).unwrap();

        let follower_hmac = Hmac::alloc(&mut follower, follower_key.into(), mode).unwrap();

        let mut prf_follower =
            Prf::alloc_master_secret(mode, &mut follower, follower_hmac).unwrap();
        prf_follower.set_start_seed(start_seed.clone());

        let mut prf_out_follower = follower.decode(prf_follower.output()).unwrap();

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

        let prf_result_leader: Vec<u8> = prf_out_leader.try_recv().unwrap().unwrap();
        let prf_result_follower: Vec<u8> = prf_out_follower.try_recv().unwrap().unwrap();

        let expected = &phash(key.to_vec(), &label_seed, iterations)[..output_len];

        assert_eq!(prf_result_leader, prf_result_follower);
        assert_eq!(prf_result_leader, expected)
    }
}
