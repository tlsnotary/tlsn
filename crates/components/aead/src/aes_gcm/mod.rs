use std::{collections::VecDeque, ops::Range};

use crate::{
    cipher::{Aes128, Cipher},
    config::MpcAeadConfig,
    AeadCipher,
};
use async_trait::async_trait;
use mpz_common::{try_join, Context};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, Repr, Vector, ViewExt,
};
use mpz_vm_core::{CallBuilder, Execute, VmExt};
use std::fmt::Debug;
use tlsn_universal_hash::UniversalHash;

mod error;
mod tag;

use error::AesGcmError;

use self::error::ErrorKind;

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

    fn alloc<R: Repr<Binary> + Copy, Vm: ViewExt + VmExt<Binary>>(
        vm: &mut Vm,
        visibility: Visibility,
    ) -> Result<R, AesGcmError> {
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

    fn asssign<R: Repr<Binary>, Vm: VmExt<Binary>>(
        vm: &mut Vm,
        value: R,
        clear: R::Clear,
    ) -> Result<(), AesGcmError> {
        vm.assign(value, clear)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))
    }

    fn prepare_keystream_block<Vm>(
        vm: &mut Vm,
        key: <Aes128 as Cipher>::Key,
        iv: Array<U8, 4>,
        ctr_number: u32,
    ) -> Result<Keystream, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt,
    {
        let explicit_nonce: Array<U8, 8> = Self::alloc(vm, Visibility::Public)?;
        let counter: Array<U8, 4> = Self::alloc(vm, Visibility::Public)?;
        Self::asssign(vm, counter, ctr_number.to_be_bytes())?;

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

    fn prepare_mac_key<Vm>(
        vm: &mut Vm,
        key: <Aes128 as Cipher>::Key,
    ) -> Result<Array<U8, 16>, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt,
    {
        let zero: Array<U8, 16> = Self::alloc(vm, Visibility::Public)?;
        Self::asssign(vm, zero, [0_u8; 16])?;

        let aes_ecb = CallBuilder::new(<Aes128 as Cipher>::ecb())
            .arg(key)
            .arg(zero)
            .build()
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;
        let mac_key: Array<U8, 16> = vm
            .call(aes_ecb)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        Ok(mac_key)
    }
}

#[async_trait]
impl<Ctx, Vm, U> AeadCipher<Aes128, Ctx, Vm> for MpcAesGcm<U>
where
    Ctx: Context,
    Self: Send,
    Vm: VmExt<Binary> + ViewExt + Execute<Ctx> + Send,
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
        counters: Range<u32>,
    ) -> Result<(), Self::Error> {
        let block_count = counters.len();
        let key = self.key()?;
        let iv = self.iv()?;

        for ctr in counters {
            let keystream = Self::prepare_keystream_block(vm, key, iv, ctr)?;
            self.keystream.push_back(keystream);
        }

        let mac_key = Self::prepare_mac_key(vm, key)?;
        let mut j0 = VecDeque::with_capacity(block_count);

        for _ in 0..block_count {
            let j0_block = Self::prepare_keystream_block(vm, key, iv, 1)?;
            j0.push_back(j0_block);
        }

        let mac = Mac { key: mac_key, j0 };
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

    async fn start(&mut self) -> Result<(), Self::Error> {
        todo!()
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
