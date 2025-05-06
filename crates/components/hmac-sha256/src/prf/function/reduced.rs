//! Computes some hashes of the PRF locally.

use std::collections::VecDeque;

use crate::{hmac::hmac_sha256, sha256, state_to_bytes, PrfError};
use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, DecodeFutureTyped, MemoryExt, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    // The label, e.g. "master secret".
    label: &'static [u8],
    // The start seed and the label, e.g. client_random + server_random + "master_secret".
    start_seed_label: Vec<u8>,
    iterations: usize,
    state: PrfState,
    a: VecDeque<AHash>,
    p: VecDeque<PHash>,
}

#[derive(Debug)]
enum PrfState {
    InnerPartial {
        inner_partial: DecodeFutureTyped<BitVec, [u32; 8]>,
    },
    ComputeA {
        iter: usize,
        inner_partial: [u32; 8],
        msg: Vec<u8>,
    },
    ComputeP {
        iter: usize,
        inner_partial: [u32; 8],
        a_output: DecodeFutureTyped<BitVec, [u8; 32]>,
    },
    FinishLastP,
    Done,
}

impl PrfFunction {
    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn alloc_master_secret(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::MS_LABEL, outer_partial, inner_partial, 48)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::KEY_LABEL, outer_partial, inner_partial, 40)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::CF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::SF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn wants_flush(&mut self) -> bool {
        if let PrfState::Done = self.state {
            return false;
        }
        true
    }

    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        match &mut self.state {
            PrfState::InnerPartial { inner_partial } => {
                let Some(inner_partial) = inner_partial.try_recv().map_err(PrfError::vm)? else {
                    return Ok(());
                };

                self.state = PrfState::ComputeA {
                    iter: 1,
                    inner_partial,
                    msg: self.start_seed_label.clone(),
                };
                self.flush(vm)?;
            }
            PrfState::ComputeA {
                iter,
                inner_partial,
                msg,
            } => {
                let a = self.a.pop_front().expect("Prf AHash should be present");
                assign_inner_local(vm, a.inner_local, *inner_partial, msg)?;

                self.state = PrfState::ComputeP {
                    iter: *iter,
                    inner_partial: *inner_partial,
                    a_output: a.output,
                };
            }
            PrfState::ComputeP {
                iter,
                inner_partial,
                a_output,
            } => {
                let Some(output) = a_output.try_recv().map_err(PrfError::vm)? else {
                    return Ok(());
                };
                let p = self.p.pop_front().expect("Prf PHash should be present");

                let mut msg = output.to_vec();
                msg.extend_from_slice(&self.start_seed_label);

                assign_inner_local(vm, p.inner_local, *inner_partial, &msg)?;

                if *iter == self.iterations {
                    self.state = PrfState::FinishLastP;
                } else {
                    self.state = PrfState::ComputeA {
                        iter: *iter + 1,
                        inner_partial: *inner_partial,
                        msg: output.to_vec(),
                    }
                };
            }
            PrfState::FinishLastP => self.state = PrfState::Done,
            _ => (),
        }

        Ok(())
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = start_seed_label;
    }

    pub(crate) fn output(&self) -> Vec<Array<U8, 32>> {
        self.p.iter().map(|p| p.output).collect()
    }

    fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        outer_partial: Sha256,
        inner_partial: Sha256,
        len: usize,
    ) -> Result<Self, PrfError> {
        assert!(len > 0, "cannot compute 0 bytes for prf");

        let iterations = len / 32 + ((len % 32) != 0) as usize;

        let (inner_partial, _) = inner_partial
            .state()
            .expect("state should be set for inner_partial");
        let inner_partial = vm.decode(inner_partial).map_err(PrfError::vm)?;

        let mut prf = Self {
            label,
            start_seed_label: vec![],
            iterations,
            state: PrfState::InnerPartial { inner_partial },
            a: VecDeque::new(),
            p: VecDeque::new(),
        };

        for _ in 0..iterations {
            // setup A[i]
            let inner_local: Array<U8, 32> = vm.alloc().map_err(PrfError::vm)?;
            let output = hmac_sha256(vm, outer_partial.clone(), inner_local)?;

            let output = vm.decode(output).map_err(PrfError::vm)?;
            let a_hash = AHash {
                inner_local,
                output,
            };

            prf.a.push_front(a_hash);

            // setup P[i]
            let inner_local: Array<U8, 32> = vm.alloc().map_err(PrfError::vm)?;
            let output = hmac_sha256(vm, outer_partial.clone(), inner_local)?;
            let p_hash = PHash {
                inner_local,
                output,
            };
            prf.p.push_front(p_hash);
        }

        Ok(prf)
    }
}

fn assign_inner_local(
    vm: &mut dyn Vm<Binary>,
    inner_local: Array<U8, 32>,
    inner_partial: [u32; 8],
    msg: &[u8],
) -> Result<(), PrfError> {
    let inner_local_value = sha256(inner_partial, 64, msg);

    vm.mark_public(inner_local).map_err(PrfError::vm)?;
    vm.assign(inner_local, state_to_bytes(inner_local_value))
        .map_err(PrfError::vm)?;
    vm.commit(inner_local).map_err(PrfError::vm)?;

    Ok(())
}

/// Like PHash but stores the output as the decoding future because in the reduced Prf we need to
/// decode this output.
#[derive(Debug)]
struct AHash {
    inner_local: Array<U8, 32>,
    output: DecodeFutureTyped<BitVec, [u8; 32]>,
}

#[derive(Debug, Clone, Copy)]
struct PHash {
    inner_local: Array<U8, 32>,
    output: Array<U8, 32>,
}
