use crate::PrfError;
use mpz_circuits::circuits::sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction;

impl PrfFunction {
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn alloc_master_secret(
        seed: Vector<U8>,
        outer_partial: Array<U8, 32>,
        inner_local: Array<U8, 32>,
    ) -> Vector<U8> {
        Self::alloc(Self::MS_LABEL, seed, outer_partial, inner_local, 48)
    }

    pub(crate) fn alloc_key_expansion(
        seed: Vector<U8>,
        outer_partial: Array<U8, 32>,
        inner_local: Array<U8, 32>,
    ) -> Vector<U8> {
        Self::alloc(Self::KEY_LABEL, seed, outer_partial, inner_local, 40)
    }

    pub(crate) fn alloc_client_finished(
        seed: Vector<U8>,
        outer_partial: Array<U8, 32>,
        inner_local: Array<U8, 32>,
    ) -> Vector<U8> {
        Self::alloc(Self::CF_LABEL, seed, outer_partial, inner_local, 12)
    }

    pub(crate) fn alloc_server_finished(
        seed: Vector<U8>,
        outer_partial: Array<U8, 32>,
        inner_local: Array<U8, 32>,
    ) -> Vector<U8> {
        Self::alloc(Self::SF_LABEL, seed, outer_partial, inner_local, 12)
    }

    pub(crate) fn compute_inner_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U8, 32>, PrfError> {
        todo!()
    }

    pub(crate) fn compute_outer_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U8, 32>, PrfError> {
        todo!()
    }

    pub(crate) fn compute_inner_local(
        vm: &mut dyn Vm<Binary>,
        inner_partial: [u8; 32],
        message: Vec<u8>,
    ) -> Result<Array<U8, 32>, PrfError> {
        let inner_partial: [u32; 8] = convert(inner_partial);
        let inner = sha256(inner_partial, 64, &message);

        let inner_ref: Array<U8, 32> = vm.alloc().map_err(PrfError::vm)?;
        vm.mark_public(inner_ref).map_err(PrfError::vm)?;
        vm.assign(inner_ref, inner).map_err(PrfError::vm)?;
        vm.commit(inner_ref).map_err(PrfError::vm)?;

        Ok(inner_ref)
    }

    fn alloc(
        label: &[u8],
        seed: Vector<U8>,
        outer_partial: Array<U8, 32>,
        inner_local: Array<U8, 32>,
        len: usize,
    ) -> Vector<U8> {
        todo!()
    }
}

fn convert(input: [u8; 32]) -> [u32; 8] {
    let mut output = [0_u32; 8];
    for (k, byte_chunk) in input.chunks_exact(4).enumerate() {
        let byte_chunk: [u8; 4] = byte_chunk.try_into().unwrap();
        let value = u32::from_be_bytes(byte_chunk);
        output[k] = value;
    }
    output
}
