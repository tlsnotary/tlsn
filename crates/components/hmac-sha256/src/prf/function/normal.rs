//! Computes the whole PRF in MPC.

use crate::{hmac::hmac_sha256, PrfError};
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    // The label, e.g. "master secret".
    label: &'static [u8],
    state: State,
    // The start seed and the label, e.g. client_random + server_random + "master_secret".
    start_seed_label: Vec<u8>,
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
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::MS_LABEL, outer_partial, inner_partial, 48, 64)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::KEY_LABEL, outer_partial, inner_partial, 40, 64)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::CF_LABEL, outer_partial, inner_partial, 12, 32)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::SF_LABEL, outer_partial, inner_partial, 12, 32)
    }

    pub(crate) fn wants_flush(&self) -> bool {
        match self.state {
            State::Computing => true,
            State::Finished => false,
        }
    }

    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        if let State::Computing = self.state {
            let a = self.a.first().expect("prf should be allocated");
            let msg = *a.msg.first().expect("message for prf should be present");

            let msg_value = self.start_seed_label.clone();

            vm.mark_public(msg).map_err(PrfError::vm)?;
            vm.assign(msg, msg_value).map_err(PrfError::vm)?;
            vm.commit(msg).map_err(PrfError::vm)?;

            self.state = State::Finished;
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
        output_len: usize,
        seed_len: usize,
    ) -> Result<Self, PrfError> {
        let mut prf = Self {
            label,
            state: State::Computing,
            start_seed_label: vec![],
            a: vec![],
            p: vec![],
        };

        assert!(output_len > 0, "cannot compute 0 bytes for prf");

        let iterations = output_len / 32 + ((output_len % 32) != 0) as usize;

        let msg_len_a = label.len() + seed_len;
        let seed_label_ref: Vector<U8> = vm.alloc_vec(msg_len_a).map_err(PrfError::vm)?;
        let mut msg_a = seed_label_ref;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial.clone(), inner_partial.clone(), &[msg_a])?;
            msg_a = Vector::<U8>::from(a.output);
            prf.a.push(a);

            let p = PHash::alloc(
                vm,
                outer_partial.clone(),
                inner_partial.clone(),
                &[msg_a, seed_label_ref],
            )?;
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

#[derive(Debug, Clone)]
struct PHash {
    msg: Vec<Vector<U8>>,
    output: Array<U8, 32>,
}

impl PHash {
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
        msg: &[Vector<U8>],
    ) -> Result<Self, PrfError> {
        let mut inner_local = inner_partial;

        msg.iter().for_each(|m| inner_local.update(m));
        inner_local.compress(vm)?;
        let inner_local = inner_local.finalize(vm)?;

        let output = hmac_sha256(vm, outer_partial, inner_local)?;
        let p_hash = Self {
            msg: msg.to_vec(),
            output,
        };
        Ok(p_hash)
    }
}
