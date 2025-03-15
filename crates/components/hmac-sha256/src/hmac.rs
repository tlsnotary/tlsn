use crate::{sha256::Sha256, PrfError};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, ToRaw, Vector,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct HmacSha256 {
    inner_local: Option<Array<U8, 32>>,
    outer_partial: Option<Array<U8, 32>>,
}

impl HmacSha256 {
    pub(crate) fn new(key: Array<U8, 64>) -> Self {
        Self {
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
}
