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
use mpz_memory_core::{
    binary::{Binary, U8},
    Vector,
};
use mpz_vm_core::VmExt;

#[async_trait]
pub trait AeadCipher<Ctx: Context, Vm: VmExt<Binary>> {
    /// The error type for the AEAD.
    type Error: std::error::Error + Send + Sync + 'static;

    fn set_key<C: Cipher>(&mut self, key: C::Key) -> Result<(), Self::Error>;

    async fn setup(&mut self) -> Result<(), Self::Error>;

    async fn preprocess(&mut self) -> Result<(), Self::Error>;

    async fn encrypt(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
        ciphertext: Vector<U8>,
        aad: Vector<U8>,
    ) -> Result<Vector<U8>, Self::Error>;

    async fn decrypt(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
        plaintext: Vector<U8>,
        aad: Vector<U8>,
    ) -> Result<Vector<U8>, Self::Error>;

    async fn decode_key(&mut self) -> Result<(), Self::Error>;
}
