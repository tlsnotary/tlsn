//! This crate provides implementations of 2PC AEADs for authenticated
//! encryption with a shared key.
//!
//! Both parties can work together to encrypt and decrypt messages with
//! different visibility configurations. See [`Aead`] for more information on
//! the interface.
//!
//! For example, one party can privately provide the plaintext to encrypt, while
//! both parties can see the ciphertext and the tag. Or, both parties can
//! cooperate to decrypt a ciphertext and verify the tag, while only one party
//! can see the plaintext.

//#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod aes_gcm;
pub mod cipher;
pub mod config;

use async_trait::async_trait;
use cipher::Cipher;
use mpz_common::Context;
use mpz_memory_core::{binary::Binary, Repr};
use mpz_vm_core::VmExt;

#[async_trait]
pub trait AeadCipher<C: Cipher, Ctx: Context, Vm: VmExt<Binary>> {
    /// The error type for the AEAD.
    type Error: std::error::Error + Send + Sync + 'static;

    fn setup(&mut self) -> Result<(), Self::Error>;

    async fn preprocess(
        &mut self,
        ctx: &mut Ctx,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<(), Self::Error>;

    fn set_key(&mut self, key: C::Key) -> Result<(), Self::Error>;

    fn set_iv(&mut self, key: C::Iv) -> Result<(), Self::Error>;

    async fn start(&mut self, ctx: &mut Ctx, vm: &mut Vm) -> Result<(), Self::Error>;

    fn encrypt(&mut self, len: usize) -> Encrypt<C>;

    fn decrypt(
        &mut self,
        vm: &mut Vm,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        start_counter: u32,
    ) -> Decrypt<C>;

    async fn decode_key_and_iv(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
    ) -> Result<
        Option<(
            <<C as Cipher>::Key as Repr<Binary>>::Clear,
            <<C as Cipher>::Iv as Repr<Binary>>::Clear,
        )>,
        Self::Error,
    >;
}

pub struct Encrypt<C: Cipher> {
    key: C::Key,
    iv: C::Iv,
    nonce: C::Nonce,
    counter: C::Counter,
    message: C::Block,
    output: C::Block,
}

impl<C: Cipher> Encrypt<C> {
    pub fn set_nonce(&mut self) -> &mut Self {
        todo!()
    }

    pub fn set_counter(&mut self) -> &mut Self {
        todo!()
    }
}

pub struct Decrypt<C: Cipher> {}
