use crate::PrfError;
use mpz_circuits::circuits::SHA256_COMPRESS;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};

#[derive(Debug, Default)]
pub(crate) struct Sha256 {
    state: Option<Array<U32, 8>>,
    chunks: Vec<Array<U8, 64>>,
    processed: u32,
}

impl Sha256 {
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_state(&mut self, state: Array<U32, 8>) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub(crate) fn set_processed(&mut self, processed: u32) -> &mut Self {
        self.processed = processed;
        self
    }

    pub(crate) fn update(&mut self, data: Array<U8, 64>) -> &mut Self {
        self.chunks.push(data);
        self
    }

    pub(crate) fn alloc(
        self,
        vm: &mut dyn Vm<Binary>,
        data: Vector<U8>,
    ) -> Result<Array<U32, 8>, PrfError> {
        let mut state = if let Some(state) = self.state {
            state
        } else {
            Self::assign_iv(vm)?
        };

        let processed = self.processed + 64 * self.chunks.len() as u32;
        for chunk in self.chunks {
            state = Self::compute_state(vm, state, chunk)?;
        }

        let padded = Self::pad_data(data, processed);
        Self::compute_state(vm, state, padded)
    }

    fn assign_iv(vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        let iv: Array<U32, 8> = vm.alloc().map_err(PrfError::vm)?;

        vm.mark_public(iv).map_err(PrfError::vm)?;
        vm.assign(iv, Self::IV).map_err(PrfError::vm)?;
        vm.commit(iv).map_err(PrfError::vm)?;

        Ok(iv)
    }

    fn compute_state(
        vm: &mut dyn Vm<Binary>,
        state: Array<U32, 8>,
        data: Array<U8, 64>,
    ) -> Result<Array<U32, 8>, PrfError> {
        let compress = Call::builder(SHA256_COMPRESS.clone())
            .arg(state)
            .arg(data)
            .build()
            .map_err(PrfError::vm)?;

        vm.call(compress).map_err(PrfError::vm)
    }

    fn pad_data(data: Vector<U8>, processed: u32) -> Array<U8, 64> {
        todo!()
    }
}
