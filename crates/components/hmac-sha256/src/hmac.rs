use crate::{sha256::Sha256, PrfError};
use mpz_circuits::circuits::sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, MemoryExt, ToRaw, Vector, ViewExt,
    },
    Vm,
};

pub(crate) struct HmacSha256 {
    key: Array<U8, 64>,
    inner_local: Option<Array<U8, 32>>,
    outer_partial: Option<Array<U8, 32>>,
}

impl HmacSha256 {
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    pub(crate) fn new(key: Array<U8, 64>) -> Self {
        Self {
            key,
            outer_partial: None,
            inner_local: None,
        }
    }

    pub(crate) fn set_inner_local(&mut self, inner_local: Array<U8, 32>) {
        self.inner_local = Some(inner_local);
    }

    pub(crate) fn set_outer_partial(&mut self, outer_partial: Array<U8, 32>) {
        self.outer_partial = Some(outer_partial);
    }

    pub(crate) fn finalize(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 32>, PrfError> {
        let Some(inner_local) = self.inner_local else {
            return Err(PrfError::state("Inner local hash not set"));
        };

        let Some(outer_partial) = self.outer_partial else {
            return Err(PrfError::state("Outer partial hash not set"));
        };

        let outer_partial: Array<U32, 8> =
            <Array<U32, 8> as FromRaw<Binary>>::from_raw(outer_partial.to_raw());

        let mut outer = Sha256::new();
        outer.set_state(outer_partial).set_chunk_count(1);
        outer.finalize(vm, Vector::from_raw(inner_local.to_raw()))
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

    pub(crate) fn compute_inner_partial(
        &self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<Array<U8, 32>, PrfError> {
        todo!()
    }

    fn compute_outer_partial(&self) -> Result<Array<U8, 32>, PrfError> {
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
