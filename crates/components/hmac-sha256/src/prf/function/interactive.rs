use crate::{hmac::HmacSha256, prf::function::compute_partial, sha256::Sha256, PrfError};
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
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    pub(crate) const MS_LABEL: &[u8] = b"master secret";
    pub(crate) const KEY_LABEL: &[u8] = b"key expansion";
    pub(crate) const CF_LABEL: &[u8] = b"client finished";
    pub(crate) const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn alloc_master_secret(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::MS_LABEL, 48, 64)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::KEY_LABEL, 40, 64)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::CF_LABEL, 12, 32)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::SF_LABEL, 12, 32)
    }

    pub(crate) fn make_progress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        let assigned = self.assigned;

        if !assigned {
            let a = self.a.first_mut().expect("prf should be allocated");
            let msg = a.msg;

            let msg_value = self
                .start_seed_label
                .clone()
                .expect("seed should be assigned by now");

            vm.mark_public(msg).map_err(PrfError::vm)?;
            vm.assign(msg, msg_value).map_err(PrfError::vm)?;
            vm.commit(msg).map_err(PrfError::vm)?;
        }

        self.assigned = true;
        Ok(assigned)
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
        key: Vector<U8>,
        label: &'static [u8],
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

        assert!(
            key.len() <= 64,
            "keys longer than 64 bits are not supported"
        );
        assert!(output_len > 0, "cannot compute 0 bytes for prf");

        let iterations = output_len / 32 + ((output_len % 32) != 0) as usize;

        let outer_partial = compute_partial(vm, key, Self::OPAD)?;
        let inner_partial = compute_partial(vm, key, Self::IPAD)?;

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
