use crate::{circuit::CipherCircuit, config::CipherConfig, Cipher, EcbBlock, Keystream};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_memory_core::{binary::Binary, MemoryExt, Repr, StaticSize, View, ViewExt};
use mpz_vm_core::{CallBuilder, Execute, Vm, VmExt};
use std::{collections::VecDeque, fmt::Debug};

mod circuit;
mod error;

use circuit::Aes128;
use error::{AesError, ErrorKind};

pub struct MpcAes {
    config: CipherConfig,
    key: Option<<Aes128 as CipherCircuit>::Key>,
    iv: Option<<Aes128 as CipherCircuit>::Iv>,
}

impl Debug for MpcAes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAes")
            .field("config", &self.config)
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .finish()
    }
}

impl MpcAes {
    pub fn new(config: CipherConfig) -> Self {
        Self {
            config,
            key: None,
            iv: None,
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

    fn alloc_public<R, V>(vm: &mut V) -> Result<R, AesError>
    where
        R: Repr<Binary> + StaticSize<Binary> + Copy,
        V: View<Binary> + Vm<Binary>,
    {
        let value = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        vm.mark_public(value)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(value)
    }
}

#[async_trait]
impl<Ctx, V> Cipher<Aes128, Ctx, V> for MpcAes
where
    Ctx: Context,
    Self: Send,
    V: Vm<Binary> + View<Binary> + Execute<Ctx> + Send,
{
    type Error = AesError;

    fn set_key(&mut self, key: <Aes128 as CipherCircuit>::Key) {
        self.key = Some(key);
    }

    fn set_iv(&mut self, iv: <Aes128 as CipherCircuit>::Iv) {
        self.iv = Some(iv);
    }

    fn alloc(&mut self, vm: &mut V, block_count: usize) -> Result<Keystream<Aes128>, Self::Error> {
        let key = self.key()?;
        let iv = self.iv()?;

        let mut keystream = Keystream::<Aes128>::new(key, iv);
        let mut circuits = VecDeque::with_capacity(block_count);

        // outputs need to be allocated sequentially so we do two separate for loops.
        for _ in 0..block_count {
            let explicit_nonce: <Aes128 as CipherCircuit>::Nonce = MpcAes::alloc_public(vm)?;
            let counter: <Aes128 as CipherCircuit>::Counter = MpcAes::alloc_public(vm)?;

            let aes_ctr = CallBuilder::new(<Aes128 as CipherCircuit>::ctr())
                .arg(key)
                .arg(iv)
                .arg(explicit_nonce)
                .arg(counter)
                .build()
                .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

            keystream.explicit_nonces.push_back(explicit_nonce);
            keystream.counters.push_back(counter);
            circuits.push_back(aes_ctr);
        }

        for _ in 0..block_count {
            let aes_ctr = circuits
                .pop_front()
                .expect("Enough aes-ctr circuits should be available");
            let output: <Aes128 as CipherCircuit>::Block = vm
                .call(aes_ctr)
                .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

            keystream.outputs.push_back(output);
        }

        Ok(keystream)
    }

    fn alloc_block(&mut self, vm: &mut V) -> Result<EcbBlock<Aes128>, Self::Error> {
        todo!()
    }
}
