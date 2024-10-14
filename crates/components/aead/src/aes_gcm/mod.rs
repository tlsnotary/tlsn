use std::collections::VecDeque;

use crate::{
    cipher::CipherCircuit,
    config::{MpcAeadConfig, Role},
    Cipher, DecryptPrivate, DecryptPublic, Encrypt, KeystreamBlock,
};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, Repr, StaticSize, ViewExt,
};
use mpz_vm_core::{CallBuilder, Execute, VmExt};
use rand::{distributions::Standard, prelude::Distribution, thread_rng, Rng};
use std::fmt::Debug;

mod circuit;
mod error;
mod ghash;

use circuit::Aes128;
use error::{AesGcmError, ErrorKind};
pub use ghash::GhashPrep;

pub struct MpcAesGcm {
    config: MpcAeadConfig,
    key: <Aes128 as CipherCircuit>::Key,
    iv: <Aes128 as CipherCircuit>::Iv,
    aes_ctr: VecDeque<KeystreamBlock<Aes128>>,
    mac: Option<GhashPrep>,
}

impl Debug for MpcAesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAesGcm")
            .field("config", &self.config)
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .field("aes_ctr", &self.aes_ctr)
            .field("mac", &self.mac)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
enum Visibility {
    Private,
    Public,
    Blind,
}

impl MpcAesGcm {
    pub fn new(
        config: MpcAeadConfig,
        key: <Aes128 as CipherCircuit>::Key,
        iv: <Aes128 as CipherCircuit>::Iv,
    ) -> Self {
        Self {
            config,
            key,
            iv,
            aes_ctr: VecDeque::default(),
            mac: None,
        }
    }

    fn key(&self) -> <Aes128 as CipherCircuit>::Key {
        self.key
    }

    fn iv(&self) -> <Aes128 as CipherCircuit>::Iv {
        self.iv
    }

    fn alloc<R, Vm>(vm: &mut Vm, visibility: Visibility) -> Result<R, AesGcmError>
    where
        R: Repr<Binary> + StaticSize<Binary> + Copy,
        Vm: ViewExt<Binary> + VmExt<Binary>,
    {
        let value = vm
            .alloc()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        match visibility {
            Visibility::Private => vm.mark_private(value),
            Visibility::Public => vm.mark_public(value),
            Visibility::Blind => vm.mark_blind(value),
        }
        .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        Ok(value)
    }

    fn asssign<R, Vm>(vm: &mut Vm, value: R, clear: R::Clear) -> Result<(), AesGcmError>
    where
        R: Repr<Binary>,
        Vm: VmExt<Binary>,
    {
        vm.assign(value, clear)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))
    }

    fn commit<R, Vm>(vm: &mut Vm, value: R) -> Result<(), AesGcmError>
    where
        R: Repr<Binary>,
        Vm: VmExt<Binary>,
    {
        vm.commit(value)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))
    }

    fn prepare_keystream<Vm>(
        vm: &mut Vm,
        key: <Aes128 as CipherCircuit>::Key,
        iv: Array<U8, 4>,
    ) -> Result<KeystreamBlock<Aes128>, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let explicit_nonce: Array<U8, 8> = Self::alloc(vm, Visibility::Public)?;
        let counter: Array<U8, 4> = Self::alloc(vm, Visibility::Public)?;

        // Visibility of message is not known at this point, so we just allocate.
        let message: Array<U8, 16> = vm
            .alloc()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let aes_ctr = CallBuilder::new(<Aes128 as CipherCircuit>::ctr())
            .arg(key)
            .arg(iv)
            .arg(explicit_nonce)
            .arg(counter)
            .arg(message)
            .build()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let output: Array<U8, 16> = vm
            .call(aes_ctr)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let aes_ctr = KeystreamBlock::<Aes128> {
            explicit_nonce,
            counter,
            input: message,
            output,
        };

        Ok(aes_ctr)
    }

    fn compute_keystream<Vm>(
        &mut self,
        vm: &mut Vm,
        key: <Aes128 as CipherCircuit>::Key,
        iv: Array<U8, 4>,
        block_count: usize,
    ) -> Result<Vec<KeystreamBlock<Aes128>>, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        if self.aes_ctr.len() >= block_count {
            Ok::<_, AesGcmError>(self.aes_ctr.drain(..block_count).collect())
        } else {
            let mut keystream: Vec<KeystreamBlock<Aes128>> = self.aes_ctr.drain(..).collect();
            for _ in 0..(block_count - keystream.len()) {
                let aes_ctr_block = Self::prepare_keystream(vm, key, iv)?;
                keystream.push(aes_ctr_block);
            }
            Ok(keystream)
        }
    }

    fn prepare_mac<Vm>(
        role: Role,
        vm: &mut Vm,
        key: <Aes128 as CipherCircuit>::Key,
        iv: <Aes128 as CipherCircuit>::Iv,
        record_count: usize,
    ) -> Result<GhashPrep, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let mut j0 = VecDeque::with_capacity(record_count);
        for _ in 0..record_count {
            let j0_block = Self::prepare_keystream(vm, key, iv)?;
            j0.push_back(j0_block);
        }

        let (mac_key, otp) = Self::prepare_mac_key(role, vm, key)?;

        let ghash = GhashPrep {
            role,
            otp,
            mac_key,
            j0,
        };

        Ok(ghash)
    }

    fn prepare_mac_key<Vm>(
        role: Role,
        vm: &mut Vm,
        key: <Aes128 as CipherCircuit>::Key,
    ) -> Result<(Array<U8, 16>, [u8; 16]), AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let zero: Array<U8, 16> = Self::alloc(vm, Visibility::Public)?;
        Self::asssign(vm, zero, [0_u8; 16])?;
        Self::commit(vm, zero)?;

        let mut rng = thread_rng();
        let mut otp_0: Array<U8, 16> = Self::alloc(vm, Visibility::Private)?;
        let otp_value: [u8; 16] = rng.gen();
        Self::asssign(vm, otp_0, otp_value)?;
        Self::commit(vm, otp_0)?;

        let mut otp_1: Array<U8, 16> = Self::alloc(vm, Visibility::Blind)?;
        Self::commit(vm, otp_1)?;

        if let Role::Follower = role {
            std::mem::swap(&mut otp_0, &mut otp_1);
        }

        let aes_shared = CallBuilder::new(<Aes128 as CipherCircuit>::ecb_shared())
            .arg(key)
            .arg(zero)
            .arg(otp_0)
            .arg(otp_1)
            .build()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let mac_key: Array<U8, 16> = vm
            .call(aes_shared)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        Ok((mac_key, otp_value))
    }

    fn decode_for_leader<R, Vm>(
        role: Role,
        vm: &mut Vm,
        value: R,
    ) -> Result<(R, Option<R::Clear>), AesGcmError>
    where
        R: Repr<Binary> + StaticSize<Binary> + Copy,
        R::Clear: Copy,
        Vm: VmExt<Binary> + ViewExt<Binary>,
        Standard: Distribution<R::Clear>,
    {
        let (otp, otp_value): (R, Option<R::Clear>) = match role {
            Role::Leader => {
                let mut rng = thread_rng();
                let otp = Self::alloc(vm, Visibility::Private)?;
                let otp_value: R::Clear = rng.gen();

                Self::asssign(vm, otp, otp_value)?;
                Self::commit(vm, otp)?;

                (otp, Some(otp_value))
            }
            Role::Follower => {
                let otp = Self::alloc(vm, Visibility::Blind)?;
                Self::commit(vm, otp)?;

                (otp, None)
            }
        };

        let otp_circuit = CallBuilder::new(<Aes128 as CipherCircuit>::otp())
            .arg(value)
            .arg(otp)
            .build()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let value = vm
            .call(otp_circuit)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        Ok((value, otp_value))
    }
}

#[async_trait]
impl<Ctx, Vm> Cipher<Aes128, Ctx, Vm> for MpcAesGcm
where
    Ctx: Context,
    Self: Send,
    Vm: VmExt<Binary> + ViewExt<Binary> + Execute<Ctx> + Send,
{
    type Error = AesGcmError;
    type MacPrep = GhashPrep;

    async fn preprocess(
        &mut self,
        ctx: &mut Ctx,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<(), Self::Error> {
        let key = self.key();
        let iv = self.iv();

        for _ in 0..block_count {
            let aes_ctr = Self::prepare_keystream(vm, key, iv)?;
            self.aes_ctr.push_back(aes_ctr);
        }

        // One TLS record fits 2^17 bits, and one AES block fits 2^7 bits.
        // So we need one j0 block per 2^10 AES blocks.
        let record_count = (block_count >> 10) + (block_count % 1024);
        let mac = Self::prepare_mac(self.config.role(), vm, key, iv, record_count)?;
        self.mac = Some(mac);

        vm.preprocess(ctx)
            .await
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        Ok(())
    }

    async fn compute_mac(&mut self, vm: &mut Vm) -> Result<Self::MacPrep, Self::Error> {
        let key = self.key();
        let iv = self.iv();

        let mac_prep = match self.mac.take() {
            Some(mac_prep) => mac_prep,
            None => Self::prepare_mac(self.config.role(), vm, key, iv, 0)?,
        };

        Ok(mac_prep)
    }

    fn encrypt(&mut self, vm: &mut Vm, len: usize) -> Result<Encrypt<Aes128>, AesGcmError> {
        let block_count = (len / 16) + (len % 16 != 0) as usize;

        let key = self.key();
        let iv = self.iv();

        let keystream: Vec<KeystreamBlock<Aes128>> =
            self.compute_keystream(vm, key, iv, block_count)?;
        let encrypt = Encrypt { keystream };

        Ok(encrypt)
    }

    fn decrypt_private(
        &mut self,
        vm: &mut Vm,
        len: usize,
    ) -> Result<DecryptPrivate<Aes128>, AesGcmError> {
        let block_count = (len / 16) + (len % 16 != 0) as usize;

        let key = self.key();
        let iv = self.iv();

        let mut keystream: Vec<KeystreamBlock<Aes128>> =
            self.compute_keystream(vm, key, iv, block_count)?;

        let otps: Option<Vec<[u8; 16]>> = match self.config.role() {
            Role::Leader => {
                let mut otps = Vec::with_capacity(keystream.len());
                for block in keystream.iter_mut() {
                    let (output, otp) = Self::decode_for_leader(Role::Leader, vm, block.output)?;
                    block.output = output;
                    otps.push(otp.expect("Leader should get one-time pad"));
                }
                Some(otps)
            }
            Role::Follower => {
                for block in keystream.iter_mut() {
                    let (output, _) = Self::decode_for_leader(Role::Follower, vm, block.output)?;
                    block.output = output;
                }
                None
            }
        };

        let decrypt = DecryptPrivate { keystream, otps };

        Ok(decrypt)
    }

    fn decrypt_public(
        &mut self,
        vm: &mut Vm,
        len: usize,
    ) -> Result<DecryptPublic<Aes128>, AesGcmError> {
        let block_count = (len / 16) + (len % 16 != 0) as usize;

        let key = self.key();
        let iv = self.iv();

        let keystream: Vec<KeystreamBlock<Aes128>> =
            self.compute_keystream(vm, key, iv, block_count)?;
        let decrypt = DecryptPublic { keystream };

        Ok(decrypt)
    }

    async fn decode_key_and_iv(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
    ) -> Result<
        Option<(
            <<Aes128 as CipherCircuit>::Key as Repr<Binary>>::Clear,
            <<Aes128 as CipherCircuit>::Iv as Repr<Binary>>::Clear,
        )>,
        Self::Error,
    > {
        let key = self.key();
        let iv = self.iv();

        let (key, otp_key) = Self::decode_for_leader(self.config.role(), vm, key)?;
        let (iv, otp_iv) = Self::decode_for_leader(self.config.role(), vm, iv)?;

        let key = vm
            .decode(key)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let iv = vm
            .decode(iv)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        vm.execute(ctx)
            .await
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
        vm.flush(ctx)
            .await
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;

        let (mut key, mut iv) =
            futures::try_join!(key, iv).map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        if let Role::Leader = self.config.role() {
            key.iter_mut()
                .zip(otp_key.expect("otp should be set for leader"))
                .for_each(|(value, otp)| *value ^= otp);
            iv.iter_mut()
                .zip(otp_iv.expect("otp should be set for leader"))
                .for_each(|(value, otp)| *value ^= otp);

            return Ok(Some((key, iv)));
        }

        Ok(None)
    }
}
