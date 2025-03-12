use mpz_circuits::{circuits::SHA256_COMPRESS, Circuit};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, Vm, VmError,
};
use std::sync::{Arc, OnceLock};

use crate::PrfError;

#[derive(Debug, Default)]
pub(crate) struct Sha256 {
    state: Option<Array<U8, 32>>,
    calls: Vec<Call>,
    outputs: Vec<Array<U8, 32>>,
    msg_len: u32,
}

impl Sha256 {
    /// The initial hash values.
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_state(&mut self, state: Array<U8, 32>) {
        self.state = Some(state);
    }

    pub(crate) fn update(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        data: Vector<U8>,
    ) -> Result<(), PrfError> {
        let state = if let Some(tail) = self.outputs.last().copied() {
            tail
        } else if let Some(state) = self.state {
            state
        } else {
            let iv: Array<U8, 32> = vm.alloc().map_err(PrfError::vm)?;
            vm.mark_public(iv).map_err(PrfError::vm)?;
            vm.assign(iv, Self::IV).map_err(PrfError::vm)?;
            vm.commit(iv).map_err(PrfError::vm)?;
            iv
        };

        Ok(())
    }

    pub(crate) fn finalize(self) -> Array<U8, 32> {
        todo!()
    }
}
