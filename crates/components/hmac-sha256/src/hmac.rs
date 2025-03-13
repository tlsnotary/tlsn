use crate::{sha256::Sha256, PrfError};
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, DecodeFutureTyped, FromRaw, MemoryExt, ToRaw, Vector, ViewExt,
    },
    Vm,
};

pub(crate) struct HmacSha256 {
    key: Array<U8, 64>,
    outer_partial: Option<Array<U8, 32>>,
    inner_local: [u8; 32],
}

impl HmacSha256 {
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    pub(crate) fn new(key: Array<U8, 64>) -> Self {
        Self {
            key,
            outer_partial: None,
        }
    }

    fn set_outer_partial(&mut self, outer_partial: Array<U8, 32>) {
        self.outer_partial = Some(outer_partial);
    }

    fn outer_partial(&self) -> Option<Array<U8, 32>> {
        self.outer_partial
    }

    pub(crate) fn compute_inner_local(
        &self,
        vm: &mut dyn Vm<Binary>,
        inner_partial: [u8; 32],
        message: Vector<U8>,
    ) -> Result<Array<U8, 32>, PrfError> {
        let inner_partial: [u32; 8] = inner_partial.tob.unwrap();

        let inner_partial_ref: Array<U32, 8> = vm.alloc().map_err(PrfError::vm)?;
        vm.mark_public(inner_partial_ref).map_err(PrfError::vm)?;
        vm.assign(inner_partial_ref, inner_partial)
            .map_err(PrfError::vm)?;
        vm.commit(inner_partial_ref).map_err(PrfError::vm)?;

        let inner = Sha256::new()
            .set_state(inner_partial_ref)
            .set_chunk_count(1);
        let inner = inner.finalize(vm, message)?;
    }

    pub fn finalize(&self) -> Result<Array<U8, 32>, PrfError> {
        let outer_partial = if let Some(outer_partial) = self.outer_partial {
            outer_partial
        } else {
            self.compute_outer_partial()?
        };

        let outer_partial: Array<U32, 8> = Array::from_raw(outer_partial.to_raw());
        let outer = Sha256::new().set_state(outer_partial).set_chunk_count(1);
        let outer = outer.finalize(vm, Vector::from_raw(inner.to_raw()))?;

        todo!()
    }

    fn compute_inner_partial(&self) -> Result<Array<U8, 32>, PrfError> {
        todo!()
    }

    fn compute_outer_partial(&self) -> Result<Array<U8, 32>, PrfError> {
        todo!()
    }
}
