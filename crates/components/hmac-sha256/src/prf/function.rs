use crate::{hmac::HmacSha256, PrfError};
use mpz_circuits::circuits::sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, MemoryExt, ToRaw, Vector, ViewExt,
    },
    Vm,
};

#[derive(Debug, Default)]
pub(crate) struct PrfFunction {
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

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn alloc_master_secret(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Vector<U8>, PrfError> {
        self.alloc(vm, key, 48)
    }

    pub(crate) fn alloc_key_expansion(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Vector<U8>, PrfError> {
        self.alloc(vm, key, 40)
    }

    pub(crate) fn alloc_client_finished(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Vector<U8>, PrfError> {
        self.alloc(vm, key, 12)
    }

    pub(crate) fn alloc_server_finished(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Vector<U8>, PrfError> {
        self.alloc(vm, key, 12)
    }

    fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
        mut len: usize,
    ) -> Result<Vector<U8>, PrfError> {
        assert!(
            key.len() <= 64,
            "keys longer than 64 bits are not supported"
        );

        if len == 0 {
            len += 1;
        }

        let iterations = len / 32 + ((len % 32) != 0) as usize;

        let outer_partial = Self::compute_outer_partial(vm, key)?;
        let inner_partial = Self::compute_inner_partial(vm, key)?;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial, inner_partial)?;
            self.a.push(a);

            let p = PHash::alloc(vm, outer_partial, inner_partial)?;
            self.p.push(p);
        }

        let output = self.p.last().unwrap().output;
        let output = Vector::from_raw(output.to_raw());

        Ok(output.into())
    }

    fn compute_inner_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U32, 8>, PrfError> {
        todo!()
    }

    fn compute_outer_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U32, 8>, PrfError> {
        todo!()
    }

    fn compute_inner_local(inner_partial: [u32; 8], message: Vec<u8>) -> [u8; 32] {
        sha256(inner_partial, 64, &message)
    }
}

#[derive(Debug, Clone)]
struct PHash {
    pub(crate) outer_partial: Array<U32, 8>,
    pub(crate) inner_partial: Array<U32, 8>,
    pub(crate) inner_local: Array<U32, 8>,
    pub(crate) output: Array<U32, 8>,
}

impl PHash {
    pub(crate) fn alloc(
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
            inner_local,
            output,
        };

        Ok(p_hash)
    }

    pub(crate) fn assign_inner_local(
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

fn convert(input: [u8; 32]) -> [u32; 8] {
    let mut output = [0_u32; 8];
    for (k, byte_chunk) in input.chunks_exact(4).enumerate() {
        let byte_chunk: [u8; 4] = byte_chunk.try_into().unwrap();
        let value = u32::from_be_bytes(byte_chunk);
        output[k] = value;
    }
    output
}
