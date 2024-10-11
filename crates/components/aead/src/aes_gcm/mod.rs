use std::collections::VecDeque;

use crate::{
    cipher::Cipher,
    config::{MpcAeadConfig, Role},
    AeadCipher,
};
use async_trait::async_trait;
use mpz_common::{try_join, Context};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, Repr, StaticSize, Vector, ViewExt,
};
use mpz_vm_core::{CallBuilder, Execute, VmExt};
use rand::{thread_rng, Rng};
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
    keystream: VecDeque<Keystream>,
    mac: Option<Mac>,
}

impl<U: Debug> Debug for MpcAesGcm<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAesGcm")
            .field("config", &self.config)
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .field("ghash", &self.ghash)
            .field("keystream", &self.keystream)
            .field("mac", &self.mac)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct Keystream {
    pub explicit_nonce: Array<U8, 8>,
    pub counter: Array<U8, 4>,
    pub output: Array<U8, 16>,
}

#[derive(Debug, Clone)]
struct Mac {
    pub otp: [u8; 16],
    pub key: Array<U8, 16>,
    pub j0: VecDeque<Keystream>,
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
            keystream: VecDeque::default(),
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

    fn prepare_keystream_block<Vm>(
        vm: &mut Vm,
        key: <Aes128 as Cipher>::Key,
        iv: Array<U8, 4>,
    ) -> Result<Keystream, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        let explicit_nonce: Array<U8, 8> = Self::alloc(vm, Visibility::Public)?;
        let counter: Array<U8, 4> = Self::alloc(vm, Visibility::Public)?;

        let aes_ctr = CallBuilder::new(<Aes128 as Cipher>::ctr())
            .arg(key)
            .arg(iv)
            .arg(explicit_nonce)
            .arg(counter)
            .build()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let output: Array<U8, 16> = vm
            .call(aes_ctr)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        let keystream = Keystream {
            explicit_nonce,
            counter,
            output,
        };

        Ok(keystream)
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
            let j0_block = Self::prepare_keystream_block(vm, key, iv)?;
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
            let keystream = Self::prepare_keystream_block(vm, key, iv)?;
            self.keystream.push_back(keystream);
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

        if let Role::Leader = self.config.role() {
            mac_key
                .iter_mut()
                .zip(otp)
                .for_each(|(key, otp)| *key ^= otp);
        }

        self.ghash.set_key(mac_key.to_vec(), ctx).await?;
        Ok(())
    }

    async fn encrypt(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
        plaintext: Vector<U8>,
        aad: Vector<U8>,
    ) -> Result<Vector<U8>, Self::Error> {
        todo!()
    }

    async fn decrypt(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
        ciphertext: Vector<U8>,
        aad: Vector<U8>,
    ) -> Result<Vector<U8>, Self::Error> {
        todo!()
    }

    async fn decode_key(&mut self) -> Result<(), Self::Error> {
        todo!()
    }
}
