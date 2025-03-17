use crate::{sha256::Sha256, PrfError};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32},
        Array, FromRaw, ToRaw, Vector,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct HmacSha256 {
    outer_partial: Array<U32, 8>,
    inner_local: Array<U32, 8>,
}

impl HmacSha256 {
    pub(crate) fn new(outer_partial: Array<U32, 8>, inner_local: Array<U32, 8>) -> Self {
        Self {
            outer_partial,
            inner_local,
        }
    }

    pub(crate) fn alloc(self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        let inner_local = Vector::from_raw(self.inner_local.to_raw());

        let mut outer = Sha256::new();
        outer
            .set_state(self.outer_partial)
            .set_processed(64)
            .update(inner_local);

        outer.alloc(vm)
    }
}
