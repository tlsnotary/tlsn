//! Computes some hashes of the PRF locally.

use crate::{convert_to_bytes, hmac::HmacSha256, sha256::sha256, PrfError};
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, DecodeFutureTyped, MemoryExt, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    label: &'static [u8],
    state: State,
    start_seed_label: Option<Vec<u8>>,
    a: Vec<PHash>,
    p: Vec<PHash>,
}

impl PrfFunction {
    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn alloc_master_secret(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::MS_LABEL, outer_partial, inner_partial, 48)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::KEY_LABEL, outer_partial, inner_partial, 40)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::CF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::SF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn wants_flush(&mut self) -> bool {
        let wants_flush = if let State::Finished = self.state {
            false
        } else {
            true
        };

        // Drive state

        wants_flush
    }

    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        if let State::Computing = self.state {
            todo!()
        }

        Ok(())
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = Some(start_seed_label);
    }

    pub(crate) fn output(&self) -> Vec<Array<U32, 8>> {
        self.p.iter().map(|p| p.output).collect()
    }

    fn poll_a(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let Some(mut message) = self.start_seed_label.clone() else {
            return Err(PrfError::state("Starting seed not set for PRF"));
        };

        for a in self.a.iter_mut() {
            if let Some(output) = a.output_decoded.try_recv().map_err(PrfError::vm)? {
                message = convert_to_bytes(output).to_vec();
                continue;
            };

            let Some(inner_partial) = a.inner_partial.poll(vm)? else {
                break;
            };

            a.assign_inner_local(vm, inner_partial, &message)?;
        }

        Ok(())
    }

    fn poll_p(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let Some(ref start_seed) = self.start_seed_label else {
            return Err(PrfError::state("Starting seed not set for PRF"));
        };

        for (i, p) in self.p.iter_mut().enumerate() {
            if p.inner_local.1 {
                continue;
            }

            let Some(message) = self.a[i].output.poll(vm)? else {
                break;
            };

            let mut message = convert_to_bytes(message).to_vec();
            message.extend_from_slice(start_seed);

            let Some(inner_partial) = p.inner_partial.poll(vm)? else {
                break;
            };

            p.assign_inner_local(vm, inner_partial, &message)?;
        }

        Ok(())
    }

    fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
        len: usize,
    ) -> Result<Self, PrfError> {
        let mut prf = Self {
            state: State::Computing,
            label,
            start_seed_label: None,
            a: vec![],
            p: vec![],
        };

        assert!(len > 0, "cannot compute 0 bytes for prf");

        let iterations = len / 32 + ((len % 32) != 0) as usize;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial, inner_partial)?;
            prf.a.push(a);

            let p = PHash::alloc(vm, outer_partial, inner_partial)?;
            prf.p.push(p);
        }

        Ok(prf)
    }
}

#[derive(Debug, Clone, Copy)]
enum State {
    Computing,
    Finished,
}

#[derive(Debug)]
struct PHash {
    state: InnerState,
    inner_partial: Array<U32, 8>,
    inner_local: Array<U8, 32>,
    output: Array<U32, 8>,
    output_decoded: DecodeFutureTyped<BitVec, [u32; 8]>,
}

impl PHash {
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        let inner_local = vm.alloc().map_err(PrfError::vm)?;
        let hmac = HmacSha256::new(outer_partial, inner_local);

        let output = hmac.alloc(vm).map_err(PrfError::vm)?;
        let output_decoded = vm.decode(output).map_err(PrfError::vm)?;

        let p_hash = Self {
            state: InnerState::Init,
            inner_partial,
            inner_local,
            output,
            output_decoded,
        };

        Ok(p_hash)
    }

    fn assign_inner_local(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        inner_partial: [u32; 8],
        msg: &[u8],
    ) -> Result<(), PrfError> {
        let inner_local_ref: Array<U8, 32> = self.inner_local;
        let inner_local = sha256(inner_partial, 64, msg);

        vm.mark_public(inner_local_ref).map_err(PrfError::vm)?;
        vm.assign(inner_local_ref, convert_to_bytes(inner_local))
            .map_err(PrfError::vm)?;
        vm.commit(inner_local_ref).map_err(PrfError::vm)?;

        self.state = InnerState::Assigned;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum InnerState {
    Init,
    Assigned,
}
