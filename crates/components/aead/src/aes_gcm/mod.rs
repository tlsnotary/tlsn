use std::collections::VecDeque;

use crate::{
    cipher::Cipher,
    config::{MpcAeadConfig, Role},
    AeadCipher, Decrypt, Encrypt,
};
use async_trait::async_trait;
use mpz_common::{try_join, Context};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, Repr, StaticSize, Vector, ViewExt,
};
use mpz_vm_core::{CallBuilder, Execute, VmExt};
use rand::{distributions::Standard, prelude::Distribution, thread_rng, Rng};
use std::fmt::Debug;
use tlsn_universal_hash::UniversalHash;

mod circuit;
mod error;
mod tag;

use circuit::Aes128;
use error::{AesGcmError, ErrorKind};

pub struct MpcAesGcm<U> {
    config: MpcAeadConfig,
    key: Option<<Aes128 as Cipher>::Key>,
    iv: Option<Array<U8, 4>>,
    ghash: U,
    aes_ctr: VecDeque<AesCtrBlock>,
    mac: Option<Mac>,
}

impl<U: Debug> Debug for MpcAesGcm<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAesGcm")
            .field("config", &self.config)
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .field("ghash", &self.ghash)
            .field("aes_ctr", &self.aes_ctr)
            .field("mac", &self.mac)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct AesCtrBlock {
    pub explicit_nonce: Array<U8, 8>,
    pub counter: Array<U8, 4>,
    pub message: Array<U8, 16>,
    pub output: Array<U8, 16>,
}

#[derive(Debug, Clone)]
struct Mac {
    pub otp: [u8; 16],
    pub key: Array<U8, 16>,
    pub j0: VecDeque<AesCtrBlock>,
}

#[derive(Debug, Clone, Copy)]
enum Visibility {
    Private,
    Public,
    Blind,
}

impl<U> MpcAesGcm<U> {
    pub fn new(config: MpcAeadConfig, ghash: U) -> Self {
        Self {
            config,
            key: None,
            iv: None,
            ghash,
            aes_ctr: VecDeque::default(),
            mac: None,
        }
    }

    fn key(&self) -> Result<<Aes128 as Cipher>::Key, AesGcmError> {
        self.key
            .ok_or(AesGcmError::new(ErrorKind::Key, "Key not set"))
    }

    fn iv(&self) -> Result<Array<U8, 4>, AesGcmError> {
        self.iv.ok_or(AesGcmError::new(ErrorKind::Iv, "Iv not set"))
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

    fn prepare_aes_ctr<Vm>(
        vm: &mut Vm,
        key: <Aes128 as Cipher>::Key,
        iv: Array<U8, 4>,
    ) -> Result<AesCtrBlock, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let explicit_nonce: Array<U8, 8> = Self::alloc(vm, Visibility::Public)?;
        let counter: Array<U8, 4> = Self::alloc(vm, Visibility::Public)?;

        // Visibility of message is not known at this point, so we just allocate.
        let message: Array<U8, 16> = vm
            .alloc()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let aes_ctr = CallBuilder::new(<Aes128 as Cipher>::ctr())
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

        let aes_ctr = AesCtrBlock {
            explicit_nonce,
            counter,
            message,
            output,
        };

        Ok(aes_ctr)
    }

    fn prepare_mac<Vm>(
        role: Role,
        vm: &mut Vm,
        key: <Aes128 as Cipher>::Key,
        iv: Array<U8, 4>,
        record_count: usize,
    ) -> Result<Mac, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let mut j0 = VecDeque::with_capacity(record_count);
        for _ in 0..record_count {
            let j0_block = Self::prepare_aes_ctr(vm, key, iv)?;
            j0.push_back(j0_block);
        }

        let (mac_key, otp) = Self::prepare_mac_key(role, vm, key)?;
        let mac = Mac {
            otp,
            key: mac_key,
            j0,
        };

        Ok(mac)
    }

    fn prepare_mac_key<Vm>(
        role: Role,
        vm: &mut Vm,
        key: <Aes128 as Cipher>::Key,
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

        let aes_shared = CallBuilder::new(<Aes128 as Cipher>::ecb_shared())
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

        let otp_circuit = CallBuilder::new(<Aes128 as Cipher>::otp())
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
impl<Ctx, Vm, U> AeadCipher<Aes128, Ctx, Vm> for MpcAesGcm<U>
where
    Ctx: Context,
    Self: Send,
    Vm: VmExt<Binary> + ViewExt<Binary> + Execute<Ctx> + Send,
    U: UniversalHash<Ctx> + Send,
{
    type Error = AesGcmError;

    fn setup(&mut self) -> Result<(), Self::Error> {
        self.ghash.setup()?;
        Ok(())
    }

    async fn preprocess(
        &mut self,
        ctx: &mut Ctx,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<(), Self::Error> {
        let key = self.key()?;
        let iv = self.iv()?;

        for _ in 0..block_count {
            let aes_ctr = Self::prepare_aes_ctr(vm, key, iv)?;
            self.aes_ctr.push_back(aes_ctr);
        }

        // One TLS record fits 2^17 bits, and one AES block fits 2^7 bits.
        // So we need one j0 block per 2^10 AES blocks.
        let record_count = (block_count >> 10) + (block_count % 1024);
        let mac = Self::prepare_mac(self.config.role(), vm, key, iv, record_count)?;
        self.mac = Some(mac);

        _ = try_join!(
            ctx,
            async {
                self.ghash
                    .preprocess(ctx)
                    .await
                    .map_err(|err| AesGcmError::new(ErrorKind::Ghash, err))
            },
            async {
                vm.preprocess(ctx)
                    .await
                    .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))
            }
        )?;

        Ok(())
    }

    fn set_key(&mut self, key: <Aes128 as Cipher>::Key) -> Result<(), Self::Error> {
        self.key = Some(key);
        Ok(())
    }

    fn set_iv(&mut self, iv: <Aes128 as Cipher>::Iv) -> Result<(), Self::Error> {
        self.iv = Some(iv);
        Ok(())
    }

    async fn start(&mut self, ctx: &mut Ctx, vm: &mut Vm) -> Result<(), Self::Error> {
        let (mac_key, otp) = match self.mac {
            Some(ref mac) => (mac.key, mac.otp),
            None => Self::prepare_mac_key(self.config.role(), vm, self.key()?)?,
        };

        vm.execute(ctx)
            .await
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
        vm.flush(ctx)
            .await
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;

        let mut mac_key = vm
            .decode(mac_key)
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?
            .await
            .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;

        match self.config.role() {
            Role::Leader => mac_key
                .iter_mut()
                .zip(otp)
                .for_each(|(key, otp)| *key ^= otp),
            Role::Follower => mac_key = otp,
        }

        self.ghash.set_key(mac_key.to_vec(), ctx).await?;
        Ok(())
    }

    fn encrypt(&mut self, len: usize) -> Encrypt<Aes128> {
        let block_count = (len / 16) + (len % 16 != 0) as usize;
        let aes_ctr: Vec<AesCtrBlock> = self.aes_ctr.drain(..block_count).collect();
        todo!()
    }

    fn decrypt(
        &mut self,
        vm: &mut Vm,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        start_counter: u32,
    ) -> Decrypt<Aes128> {
        todo!()
    }

    async fn decode_key_and_iv(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
    ) -> Result<
        Option<(
            <<Aes128 as Cipher>::Key as Repr<Binary>>::Clear,
            <<Aes128 as Cipher>::Iv as Repr<Binary>>::Clear,
        )>,
        Self::Error,
    > {
        let key = self.key()?;
        let iv = self.iv()?;

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
