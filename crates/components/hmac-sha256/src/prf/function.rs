use std::sync::Arc;

use crate::{
    hmac::HmacSha256,
    sha256::{convert_to_bytes, sha256, Sha256},
    PrfError,
};
use mpz_circuits::circuits::xor;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, MemoryExt, ToRaw, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    label: &'static [u8],
    start_seed_label: Option<Vec<u8>>,
    a: Vec<PHash>,
    p: Vec<PHash>,
}

impl PrfFunction {
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn alloc_master_secret(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::MS_LABEL, 48)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::KEY_LABEL, 40)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::CF_LABEL, 12)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::SF_LABEL, 12)
    }

    pub(crate) fn make_progress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        self.poll_a(vm)?;
        self.poll_p(vm)?;

        let finished = self
            .p
            .last()
            .expect("prf should be allocated")
            .assigned_inner_local;
        Ok(finished)
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = Some(start_seed_label);
    }

    pub(crate) fn output(&self) -> Vec<Array<U8, 32>> {
        let output = self
            .p
            .iter()
            .map(|p| <Array<U8, 32> as FromRaw<Binary>>::from_raw(p.output.to_raw()))
            .collect();
        output
    }

    fn poll_a(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let Some(mut message) = self.start_seed_label.clone() else {
            return Err(PrfError::state("Starting seed not set for PRF"));
        };

        for a in self.a.iter_mut() {
            let Some(inner_partial) = a.inner_partial_decoded else {
                a.try_recv_inner_partial(vm)?;
                break;
            };

            if !a.assigned_inner_local {
                let inner_local = Self::compute_inner_local(inner_partial, &message);
                a.assign_inner_local(vm, inner_local)?;
                a.assigned_inner_local = true;
            }
            let Some(output) = a.output_decoded else {
                a.try_recv_output(vm)?;
                break;
            };
            message = convert_to_bytes(output).to_vec();
        }

        Ok(())
    }

    fn poll_p(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let Some(start_seed) = self.start_seed_label.clone() else {
            return Err(PrfError::state("Starting seed not set for PRF"));
        };

        for (i, p) in self.p.iter_mut().enumerate() {
            let Some(message) = self.a[i].output_decoded else {
                break;
            };
            let mut message = convert_to_bytes(message).to_vec();
            message.extend_from_slice(&start_seed);

            let Some(inner_partial) = p.inner_partial_decoded else {
                p.try_recv_inner_partial(vm)?;
                break;
            };

            if !p.assigned_inner_local {
                let inner_local = Self::compute_inner_local(inner_partial, &message);
                p.assign_inner_local(vm, inner_local)?;
                p.assigned_inner_local = true;
            }
        }

        Ok(())
    }

    fn alloc(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
        label: &'static [u8],
        len: usize,
    ) -> Result<Self, PrfError> {
        let mut prf = Self {
            label,
            start_seed_label: None,
            a: vec![],
            p: vec![],
        };

        assert!(
            key.len() <= 64,
            "keys longer than 64 bits are not supported"
        );
        assert!(len > 0, "cannot compute 0 bytes for prf");

        let iterations = len / 32 + ((len % 32) != 0) as usize;

        let outer_partial = Self::compute_outer_partial(vm, key)?;
        let inner_partial = Self::compute_inner_partial(vm, key)?;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial, inner_partial)?;
            prf.a.push(a);

            let p = PHash::alloc(vm, outer_partial, inner_partial)?;
            prf.p.push(p);
        }

        Ok(prf)
    }

    fn compute_inner_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U32, 8>, PrfError> {
        Self::compute_partial(vm, key, Self::IPAD)
    }

    fn compute_outer_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U32, 8>, PrfError> {
        Self::compute_partial(vm, key, Self::OPAD)
    }

    fn compute_partial(
        vm: &mut dyn Vm<Binary>,
        data: Vector<U8>,
        mask: [u8; 64],
    ) -> Result<Array<U32, 8>, PrfError> {
        let xor = Arc::new(xor(64));

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

    fn compute_inner_local(inner_partial: [u32; 8], message: &[u8]) -> [u32; 8] {
        sha256(inner_partial, 64, message)
    }
}

#[derive(Debug, Clone)]
struct PHash {
    pub(crate) outer_partial: Array<U32, 8>,
    pub(crate) inner_partial: Array<U32, 8>,
    pub(crate) inner_partial_decoded: Option<[u32; 8]>,
    pub(crate) inner_local: Array<U32, 8>,
    pub(crate) assigned_inner_local: bool,
    pub(crate) output: Array<U32, 8>,
    pub(crate) output_decoded: Option<[u32; 8]>,
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

        let p_hash = Self {
            outer_partial,
            inner_partial,
            inner_partial_decoded: None,
            inner_local,
            assigned_inner_local: false,
            output,
            output_decoded: None,
        };

        Ok(p_hash)
    }

    fn try_recv_inner_partial(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let mut inner_partial_decoded = vm.decode(self.inner_partial).map_err(PrfError::vm)?;
        self.inner_partial_decoded = inner_partial_decoded.try_recv().map_err(PrfError::vm)?;
        Ok(())
    }

    fn try_recv_output(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let mut output_decoded = vm.decode(self.output).map_err(PrfError::vm)?;
        self.output_decoded = output_decoded.try_recv().map_err(PrfError::vm)?;
        Ok(())
    }

    fn assign_inner_local(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        inner_local: [u32; 8],
    ) -> Result<(), PrfError> {
        let inner_local_ref: Array<U32, 8> = self.inner_local;

        vm.mark_public(inner_local_ref).map_err(PrfError::vm)?;
        vm.assign(inner_local_ref, inner_local)
            .map_err(PrfError::vm)?;
        vm.commit(inner_local_ref).map_err(PrfError::vm)?;

        Ok(())
    }
}
