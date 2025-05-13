//! Computes the whole PRF in MPC.

use crate::{hmac::HmacSha256, sha256::Sha256, PrfError};
use mpz_circuits::CircuitBuilder;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct PrfFunction {
    label: &'static [u8],
    start_seed_label: Option<Vec<u8>>,
    a: Vec<PHash>,
    p: Vec<PHash>,
    assigned: bool,
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
        Self::alloc(vm, Self::MS_LABEL, outer_partial, inner_partial, 48, 64)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::KEY_LABEL, outer_partial, inner_partial, 40, 64)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::CF_LABEL, outer_partial, inner_partial, 12, 32)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::SF_LABEL, outer_partial, inner_partial, 12, 32)
    }

    pub(crate) fn make_progress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        if !self.assigned {
            let a = self.a.first_mut().expect("prf should be allocated");
            let msg = a.msg;

            let msg_value = self
                .start_seed_label
                .clone()
                .expect("seed should be assigned by now");

            vm.mark_public(msg).map_err(PrfError::vm)?;
            vm.assign(msg, msg_value).map_err(PrfError::vm)?;
            vm.commit(msg).map_err(PrfError::vm)?;
            self.assigned = true;
        }

        Ok(self.assigned)
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = Some(start_seed_label);
    }

    pub(crate) fn output(&self) -> Vec<Array<U32, 8>> {
        self.p.iter().map(|p| p.output).collect()
    }

    fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
        output_len: usize,
        seed_len: usize,
    ) -> Result<Self, PrfError> {
        let mut prf = Self {
            label,
            start_seed_label: None,
            a: vec![],
            p: vec![],
            assigned: false,
        };

        assert!(output_len > 0, "cannot compute 0 bytes for prf");

        let iterations = output_len / 32 + ((output_len % 32) != 0) as usize;

        let msg_len_a = label.len() + seed_len;
        let seed_label_ref: Vector<U8> = vm.alloc_vec(msg_len_a).map_err(PrfError::vm)?;
        let mut msg_a = seed_label_ref;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial, inner_partial, msg_a)?;
            msg_a = convert_array(vm, a.output)?.into();
            prf.a.push(a);

            let msg_p = merge_vecs(vm, vec![msg_a, seed_label_ref])?;
            let p = PHash::alloc(vm, outer_partial, inner_partial, msg_p)?;
            prf.p.push(p);
        }

        Ok(prf)
    }
}

#[derive(Debug, Clone)]
struct PHash {
    pub(crate) msg: Vector<U8>,
    pub(crate) output: Array<U32, 8>,
}

impl PHash {
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
        msg: Vector<U8>,
    ) -> Result<Self, PrfError> {
        let mut sha = Sha256::default();
        sha.set_state(inner_partial, 64)
            .update(msg)
            .add_padding(vm)?;

        let inner_local = sha.alloc(vm)?;
        let inner_local = convert_array(vm, inner_local)?;

        let hmac = HmacSha256::new(outer_partial, inner_local);
        let output = hmac.alloc(vm).map_err(PrfError::vm)?;

        let p_hash = Self { msg, output };
        Ok(p_hash)
    }
}

fn convert_array(vm: &mut dyn Vm<Binary>, input: Array<U32, 8>) -> Result<Array<U8, 32>, PrfError> {
    let circ = {
        let mut builder = CircuitBuilder::new();
        let inputs = (0..32 * 8).map(|_| builder.add_input()).collect::<Vec<_>>();

        for input in inputs.chunks_exact(4 * 8) {
            for byte in input.chunks_exact(8).rev() {
                for &feed in byte.iter() {
                    let output = builder.add_id_gate(feed);
                    builder.add_output(output);
                }
            }
        }

        Arc::new(builder.build().expect("conversion circuit is valid"))
    };

    let mut builder = Call::builder(circ);
    builder = builder.arg(input);
    let call = builder.build().map_err(PrfError::vm)?;

    vm.call(call).map_err(PrfError::vm)
}

fn merge_vecs(vm: &mut dyn Vm<Binary>, inputs: Vec<Vector<U8>>) -> Result<Vector<U8>, PrfError> {
    let len: usize = inputs.iter().map(|inp| inp.len()).sum();
    let circ = {
        let mut builder = CircuitBuilder::new();

        let feeds = (0..len * 8)
            .map(|_| builder.add_input())
            .collect::<Vec<_>>();
        for feed in feeds {
            let output = builder.add_id_gate(feed);
            builder.add_output(output);
        }

        Arc::new(builder.build().expect("merge circuit is valid"))
    };

    let mut builder = Call::builder(circ);
    for input in inputs {
        builder = builder.arg(input);
    }
    let call = builder.build().map_err(PrfError::vm)?;

    vm.call(call).map_err(PrfError::vm)
}
