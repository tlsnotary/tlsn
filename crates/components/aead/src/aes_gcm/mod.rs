use crate::{
    cipher::{Aes128, Cipher},
    config::MpcAeadConfig,
    AeadCipher,
};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Vector,
};
use mpz_vm_core::VmExt;
use tlsn_universal_hash::UniversalHash;

mod error;
use error::AesGcmError;

pub struct MpcAesGcm<U> {
    config: MpcAeadConfig,
    key: Option<<Aes128 as Cipher>::Key>,
    iv: Option<Array<U8, 4>>,
    circuit: Aes128,
    ghash: U,
}

impl<U> MpcAesGcm<U> {
    pub fn new(config: MpcAeadConfig, ghash: U) -> Self {
        Self {
            config,
            key: None,
            iv: None,
            circuit: Aes128,
            ghash,
        }
    }
}

#[async_trait]
impl<Ctx: Context, Vm: VmExt<Binary>, U: UniversalHash<Ctx>> AeadCipher<Ctx, Vm> for MpcAesGcm<U>
where
    Self: Send,
{
    type Error = AesGcmError;

    fn set_key<C: Cipher>(&mut self, _key: C::Key) -> Result<(), Self::Error> {
        todo!()
    }

    async fn setup(&mut self) -> Result<(), Self::Error> {
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
