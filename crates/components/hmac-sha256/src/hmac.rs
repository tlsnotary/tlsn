use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, Vector,
    },
    Vm,
};

use crate::{sha256::Sha256, PrfError};

pub(crate) struct Hmac<T: Digest> {
    key: Vector<U8>,
    inner: Option<T::Output>,
    outer: Option<T::Output>,
}

impl Hmac<Sha256> {
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    pub(crate) fn new(key: Vector<U8>) -> Self {
        assert!(
            key.len() <= 64,
            "HMAC-SHA256 implementation only supports keys <= 64 bytes"
        );

        Self {
            key,
            inner: None,
            outer: None,
        }
    }

    fn set_inner(&mut self, inner: Array<U8, 32>) {
        self.inner = Some(inner);
    }

    fn set_outer(&mut self, outer: Array<U8, 32>) {
        self.outer = Some(outer);
    }

    pub(crate) fn compute(
        &self,
        vm: &mut dyn Vm<Binary>,
        message: Vector<U8>,
    ) -> Result<Array<U8, 32>, PrfError> {
        let (inner, outer) = if let (Some(inner), Some(outer)) = (self.inner, self.outer) {
            (inner, outer)
        } else {
            let inner = self.compute_inner()?;
            let outer = self.compute_outer()?;
            (inner, outer)
        };
        todo!()
    }

    fn compute_inner(&self) -> Result<Array<U8, 32>, PrfError> {
        todo!()
    }

    fn compute_outer(&self) -> Result<Array<U8, 32>, PrfError> {
        todo!()
    }
}

trait Digest {
    type Output;
}

impl Digest for Sha256 {
    type Output = Array<U8, 32>;
}
