use crate::{cipher::CipherCircuit, config::CipherConfig, Cipher, Keystream};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_memory_core::{binary::Binary, MemoryExt, Repr, StaticSize, ViewExt};
use mpz_vm_core::{CallBuilder, Execute, VmExt};
use std::fmt::Debug;

mod circuit;
mod error;

use circuit::Aes128;
use error::{AesError, ErrorKind};

pub struct MpcAes {
    config: CipherConfig,
    key: Option<<Aes128 as CipherCircuit>::Key>,
    iv: Option<<Aes128 as CipherCircuit>::Iv>,
    keystream: Option<Keystream<Aes128>>,
}

impl Debug for MpcAes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAes")
            .field("config", &self.config)
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .field("keystream", &"{{...}}")
            .finish()
    }
}

impl MpcAes {
    pub fn new(config: CipherConfig) -> Self {
        Self {
            config,
            key: None,
            iv: None,
            keystream: None,
        }
    }

    pub fn key(&self) -> Result<<Aes128 as CipherCircuit>::Key, AesError> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))
    }

    pub fn iv(&self) -> Result<<Aes128 as CipherCircuit>::Iv, AesError> {
        self.iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))
    }

    fn alloc_public<R, Vm>(vm: &mut Vm) -> Result<R, AesError>
    where
        R: Repr<Binary> + StaticSize<Binary> + Copy,
        Vm: ViewExt<Binary> + VmExt<Binary>,
    {
        let value = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        vm.mark_public(value)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(value)
    }

    fn prepare_keystream<Vm>(
        &self,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<Keystream<Aes128>, AesError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let key = self.key()?;
        let iv = self.iv()?;

        let mut keystream = Keystream::<Aes128>::new(key, iv);

        for _ in 0..block_count {
            let explicit_nonce: <Aes128 as CipherCircuit>::Nonce = MpcAes::alloc_public(vm)?;
            let counter: <Aes128 as CipherCircuit>::Counter = MpcAes::alloc_public(vm)?;

            // Visibility of message is not known at this point, so we just allocate.
            let input: <Aes128 as CipherCircuit>::Block = vm
                .alloc()
                .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

            let aes_ctr = CallBuilder::new(<Aes128 as CipherCircuit>::ctr())
                .arg(key)
                .arg(iv)
                .arg(explicit_nonce)
                .arg(counter)
                .arg(input)
                .build()
                .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

            let output: <Aes128 as CipherCircuit>::Block = vm
                .call(aes_ctr)
                .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

            keystream.push(explicit_nonce, counter, input, output);
        }

        Ok(keystream)
    }
}

#[async_trait]
impl<Ctx, Vm> Cipher<Aes128, Ctx, Vm> for MpcAes
where
    Ctx: Context,
    Self: Send,
    Vm: VmExt<Binary> + ViewExt<Binary> + Execute<Ctx> + Send,
{
    type Error = AesError;

    fn set_key(&mut self, key: <Aes128 as CipherCircuit>::Key) {
        self.key = Some(key);
    }

    fn set_iv(&mut self, iv: <Aes128 as CipherCircuit>::Iv) {
        self.iv = Some(iv);
    }

    async fn preprocess(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
        block_count: usize,
    ) -> Result<(), Self::Error> {
        let new_keystream = self.prepare_keystream(vm, block_count)?;
        if let Some(ref mut keystream) = self.keystream {
            keystream.append(new_keystream);
        } else {
            self.keystream = Some(new_keystream);
        }

        vm.preprocess(ctx)
            .await
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(())
    }

    async fn compute_keystream(
        &mut self,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<Keystream<Aes128>, Self::Error> {
        let keystream = match &mut self.keystream {
            Some(keystream) => {
                let available = keystream.len();
                if available >= block_count {
                    keystream.chunk(block_count)
                } else {
                    let empty = Keystream::new(keystream.key, keystream.iv);
                    let mut keystream = std::mem::replace(keystream, empty);

                    let missing = self.prepare_keystream(vm, block_count - available)?;
                    keystream.append(missing);
                    keystream
                }
            }
            None => self.prepare_keystream(vm, block_count)?,
        };
        Ok(keystream)
    }
}
