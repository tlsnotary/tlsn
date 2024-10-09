use std::collections::VecDeque;

use crate::{
    cipher::{Aes128, Cipher},
    config::MpcAeadConfig,
    AeadCipher,
};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, Vector, ViewExt,
};
use mpz_vm_core::{Call, VmExt};
use tlsn_universal_hash::UniversalHash;

mod error;
mod tag;

use error::AesGcmError;

use self::error::ErrorKind;

pub struct MpcAesGcm<U> {
    config: MpcAeadConfig,
    key: Option<<Aes128 as Cipher>::Key>,
    iv: Option<Array<U8, 4>>,
    start_ctr: Option<Array<U8, 4>>,
    zero: Option<Array<U8, 16>>,
    ghash: U,
    preprocessed_ctr: VecDeque<Call>,
    preprocessed_ecb: Option<Call>,
}

impl<U> MpcAesGcm<U> {
    pub fn new(config: MpcAeadConfig, ghash: U) -> Self {
        Self {
            config,
            key: None,
            iv: None,
            start_ctr: None,
            zero: None,
            ghash,
            preprocessed_ctr: VecDeque::default(),
            preprocessed_ecb: None,
        }
    }

    pub fn key(&self) -> Result<<Aes128 as Cipher>::Key, AesGcmError> {
        self.key
            .ok_or(AesGcmError::new(ErrorKind::Key, "Key not set"))
    }

    pub fn iv(&self) -> Result<Array<U8, 4>, AesGcmError> {
        self.iv.ok_or(AesGcmError::new(ErrorKind::Iv, "Iv not set"))
    }

    pub fn start_ctr(&self) -> Result<Array<U8, 4>, AesGcmError> {
        self.start_ctr
            .ok_or(AesGcmError::new(ErrorKind::StartCtr, "start ctr not set"))
    }

    pub fn zero(&self) -> Result<Array<U8, 4>, AesGcmError> {
        self.iv
            .ok_or(AesGcmError::new(ErrorKind::Zero, "Zero block not set"))
    }
}

#[async_trait]
impl<Ctx: Context, Vm: VmExt<Binary> + ViewExt, U: UniversalHash<Ctx>> AeadCipher<Ctx, Vm>
    for MpcAesGcm<U>
where
    Self: Send,
{
    type Error = AesGcmError;

    fn set_key<C: Cipher>(&mut self, _key: C::Key) -> Result<(), Self::Error> {
        todo!()
    }

    async fn setup(&mut self, vm: &mut Vm) -> Result<(), Self::Error> {
        let start_ctr: Array<U8, 4> = vm
            .alloc()
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
        vm.mark_public(start_ctr)
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
        vm.assign(start_ctr, (1 as u32).to_be_bytes());
        self.start_ctr = Some(start_ctr);

        let zero: Array<U8, 16> = vm
            .alloc()
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
        vm.mark_public(zero)
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
        vm.assign(zero, [0; 16]);
        self.zero = Some(zero);

        todo!()
    }

    async fn preprocess(&mut self) -> Result<(), Self::Error> {
        todo!()
    }

    async fn encrypt(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
        ciphertext: Vector<U8>,
        aad: Vector<U8>,
    ) -> Result<Vector<U8>, Self::Error> {
        todo!()
    }

    async fn decrypt(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
        plaintext: Vector<U8>,
        aad: Vector<U8>,
    ) -> Result<Vector<U8>, Self::Error> {
        todo!()
    }

    async fn decode_key(&mut self) -> Result<(), Self::Error> {
        todo!()
    }
}
