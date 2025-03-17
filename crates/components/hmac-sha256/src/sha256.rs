use crate::PrfError;
use mpz_circuits::circuits::SHA256_COMPRESS;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, MemoryExt, ToRaw, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};

#[derive(Debug, Default)]
pub(crate) struct Sha256 {
    state: Option<Array<U32, 8>>,
    chunks: Vec<Vector<U8>>,
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

    pub(crate) fn update(&mut self, data: Vector<U8>) -> &mut Self {
        self.chunks.push(data);
        self
    }

    pub(crate) fn alloc(mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        assert!(
            self.chunks.len() >= 1,
            "Cannnot compute Sha256 on empty data"
        );

        let mut state = if let Some(state) = self.state {
            state
        } else {
            Self::assign_iv(vm)?
        };

        self.repartition();
        self.pad_data();

        for chunk in self.chunks {
            let chunk = <Array<U8, 64> as FromRaw<Binary>>::from_raw(chunk.to_raw());
            state = Self::compute_state(vm, state, chunk)?;
        }

        Ok(state)
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

    fn repartition(&mut self) {
        todo!()
    }

    fn pad_data(&mut self) {
        todo!()
    }
}
