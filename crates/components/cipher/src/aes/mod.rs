use crate::{
    cipher::CipherCircuit,
    config::{CipherConfig, Role},
    Cipher, DecryptPrivate, DecryptPublic, Encrypt, Keystream,
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
use error::{AesError, ErrorKind};
pub use ghash::GhashPrep;

pub struct MpcAes {
    config: CipherConfig,
    key: <Aes128 as CipherCircuit>::Key,
    iv: <Aes128 as CipherCircuit>::Iv,
    keystream: Keystream<Aes128>,
    mac: Option<GhashPrep>,
}

impl Debug for MpcAes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAes")
            .field("config", &self.config)
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .field("keystream", &self.keystream)
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

impl MpcAes {
    pub fn new(
        config: CipherConfig,
        key: <Aes128 as CipherCircuit>::Key,
        iv: <Aes128 as CipherCircuit>::Iv,
    ) -> Self {
        Self {
            config,
            key,
            iv,
            keystream: Keystream::<Aes128>::default(),
            mac: None,
        }
    }

    fn alloc<R, Vm>(vm: &mut Vm, visibility: Visibility) -> Result<R, AesError>
    where
        R: Repr<Binary> + StaticSize<Binary> + Copy,
        Vm: ViewExt<Binary> + VmExt<Binary>,
    {
        let value = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        match visibility {
            Visibility::Private => vm.mark_private(value),
            Visibility::Public => vm.mark_public(value),
            Visibility::Blind => vm.mark_blind(value),
        }
        .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(value)
    }

    fn asssign<R, Vm>(vm: &mut Vm, value: R, clear: R::Clear) -> Result<(), AesError>
    where
        R: Repr<Binary>,
        Vm: VmExt<Binary>,
    {
        vm.assign(value, clear)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))
    }

    fn commit<R, Vm>(vm: &mut Vm, value: R) -> Result<(), AesError>
    where
        R: Repr<Binary>,
        Vm: VmExt<Binary>,
    {
        vm.commit(value)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))
    }

    fn preprocess_keystream<Vm>(&mut self, vm: &mut Vm, block_count: usize) -> Result<(), AesError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let keystream = prepare_keystream(vm, self.key, self.iv, block_count)?;
        self.keystream.append(keystream);
        Ok(())
    }

    fn compute_keystream<Vm>(
        &mut self,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<Keystream<Aes128>, AesError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        if self.keystream.len() >= block_count {
            Ok::<_, AesError>(self.keystream.chunk(block_count))
        } else {
            self.preprocess_keystream(vm, block_count - self.keystream.len())?;
            let keystream = std::mem::take(&mut self.keystream);
            Ok(keystream)
        }
    }

    fn prepare_mac<Vm>(&mut self, vm: &mut Vm, record_count: usize) -> Result<GhashPrep, AesError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let j0_blocks = self.compute_keystream(vm, record_count)?;

        let (mac_key, otp) = self.prepare_mac_key(vm)?;
        let role = self.config.role();

        let ghash = GhashPrep {
            role,
            otp,
            mac_key,
            j0_blocks,
        };

        Ok(ghash)
    }

    fn prepare_mac_key<Vm>(&self, vm: &mut Vm) -> Result<(Array<U8, 16>, [u8; 16]), AesError>
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

        if let Role::Follower = self.config.role() {
            std::mem::swap(&mut otp_0, &mut otp_1);
        }

        let aes_shared = CallBuilder::new(<Aes128 as CipherCircuit>::ecb_shared())
            .arg(self.key)
            .arg(zero)
            .arg(otp_0)
            .arg(otp_1)
            .build()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let mac_key: Array<U8, 16> = vm
            .call(aes_shared)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok((mac_key, otp_value))
    }

    fn decode_for_leader<R, Vm>(
        role: Role,
        vm: &mut Vm,
        value: R,
    ) -> Result<(R, Option<R::Clear>), AesError>
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
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let value = vm
            .call(otp_circuit)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok((value, otp_value))
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
    type MacPrep = GhashPrep;

    async fn preprocess(
        &mut self,
        ctx: &mut Ctx,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<(), Self::Error> {
        self.preprocess_keystream(vm, block_count)?;

        // One TLS record fits 2^17 bits, and one AES block fits 2^7 bits.
        // So we need one j0 block per 2^10 AES blocks.
        let record_count = (block_count >> 10) + (block_count % 1024);
        let mac = self.prepare_mac(vm, record_count)?;
        self.mac = Some(mac);

        vm.preprocess(ctx)
            .await
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(())
    }

    async fn compute_mac(&mut self, vm: &mut Vm) -> Result<Self::MacPrep, Self::Error> {
        let mac_prep = match self.mac.take() {
            Some(mac_prep) => mac_prep,
            None => self.prepare_mac(vm, 0)?,
        };

        Ok(mac_prep)
    }

    fn encrypt(&mut self, vm: &mut Vm, len: usize) -> Result<Encrypt<Aes128>, AesError> {
        let block_count = (len / 16) + (len % 16 != 0) as usize;

        let keystream: Keystream<Aes128> = self.compute_keystream(vm, block_count)?;

        let encrypt = Encrypt { keystream };

        Ok(encrypt)
    }

    fn decrypt_private(
        &mut self,
        vm: &mut Vm,
        len: usize,
    ) -> Result<DecryptPrivate<Aes128>, AesError> {
        let block_count = (len / 16) + (len % 16 != 0) as usize;

        let mut keystream: Keystream<Aes128> = self.compute_keystream(vm, block_count)?;

        let otps: Option<Vec<[u8; 16]>> = match self.config.role() {
            Role::Leader => {
                let mut otps = Vec::with_capacity(keystream.len());
                for old_output in keystream.outputs.iter_mut() {
                    let (new_output, otp) = Self::decode_for_leader(Role::Leader, vm, *old_output)?;
                    *old_output = new_output;
                    otps.push(otp.expect("Leader should get one-time pad"));
                }
                Some(otps)
            }
            Role::Follower => {
                for old_output in keystream.outputs.iter_mut() {
                    let (new_output, _) = Self::decode_for_leader(Role::Follower, vm, *old_output)?;
                    *old_output = new_output;
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
    ) -> Result<DecryptPublic<Aes128>, AesError> {
        let block_count = (len / 16) + (len % 16 != 0) as usize;

        let keystream: Keystream<Aes128> = self.compute_keystream(vm, block_count)?;
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
        let (key, otp_key) = Self::decode_for_leader(self.config.role(), vm, self.key)?;
        let (iv, otp_iv) = Self::decode_for_leader(self.config.role(), vm, self.iv)?;

        let key = vm
            .decode(key)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let iv = vm
            .decode(iv)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        vm.execute(ctx)
            .await
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
        vm.flush(ctx)
            .await
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;

        let (mut key, mut iv) =
            futures::try_join!(key, iv).map_err(|err| AesError::new(ErrorKind::Vm, err))?;

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

fn prepare_keystream<Vm, C>(
    vm: &mut Vm,
    key: <C as CipherCircuit>::Key,
    iv: <C as CipherCircuit>::Iv,
    block_count: usize,
) -> Result<Keystream<C>, AesError>
where
    Vm: VmExt<Binary> + ViewExt<Binary>,
    C: CipherCircuit,
{
    let mut keystream = Keystream::<C>::default();

    for _ in 0..block_count {
        let explicit_nonce: <C as CipherCircuit>::Nonce = MpcAes::alloc(vm, Visibility::Public)?;
        let counter: <C as CipherCircuit>::Counter = MpcAes::alloc(vm, Visibility::Public)?;

        // Visibility of message is not known at this point, so we just allocate.
        let input: <C as CipherCircuit>::Block = vm
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

        let output: <C as CipherCircuit>::Block = vm
            .call(aes_ctr)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        keystream.push(explicit_nonce, counter, input, output);
    }

    Ok(keystream)
}
