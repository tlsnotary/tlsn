//! This crate provides implementations of 2PC ciphers for encryption with a shared key.
//!
//! Both parties can work together to encrypt and decrypt messages with different visibility
//! configurations. See [`Cipher`] for more information on the interface.
//!
//! For example, one party can privately provide the plaintext to encrypt, while both parties can
//! see the ciphertext. Or, both parties can cooperate to decrypt a ciphertext, while only one
//! party can see the plaintext.

//#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod aes;
pub mod cipher;
pub mod config;

use async_trait::async_trait;
use cipher::CipherCircuit;
use mpz_common::Context;
use mpz_memory_core::{binary::Binary, Repr};
use mpz_vm_core::VmExt;

#[async_trait]
pub trait Cipher<C: CipherCircuit, Ctx: Context, Vm: VmExt<Binary>> {
    /// The error type for the cipher.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Contains data necessary for constructing macs for the cipher
    type MacPrep;

    async fn preprocess(
        &mut self,
        ctx: &mut Ctx,
        vm: &mut Vm,
        block_count: usize,
    ) -> Result<(), Self::Error>;

    async fn compute_mac(&mut self, vm: &mut Vm) -> Result<Self::MacPrep, Self::Error>;

    fn encrypt(&mut self, vm: &mut Vm, len: usize) -> Result<Encrypt<C>, Self::Error>;

    fn decrypt_private(
        &mut self,
        vm: &mut Vm,
        len: usize,
    ) -> Result<DecryptPrivate<C>, Self::Error>;

    fn decrypt_public(&mut self, vm: &mut Vm, len: usize) -> Result<DecryptPublic<C>, Self::Error>;

    async fn decode_key_and_iv(
        &mut self,
        vm: &mut Vm,
        ctx: &mut Ctx,
    ) -> Result<
        Option<(
            <<C as CipherCircuit>::Key as Repr<Binary>>::Clear,
            <<C as CipherCircuit>::Iv as Repr<Binary>>::Clear,
        )>,
        Self::Error,
    >;
}

#[derive(Debug, Clone, Copy)]
pub struct KeystreamBlock<C: CipherCircuit> {
    explicit_nonce: C::Nonce,
    counter: C::Counter,
    input: C::Block,
    output: C::Block,
}

impl<C: CipherCircuit> KeystreamBlock<C> {
    pub fn nonce(&self) -> C::Nonce {
        self.explicit_nonce
    }

    pub fn counter(&self) -> C::Counter {
        self.counter
    }

    pub fn input(&self) -> C::Block {
        self.input
    }

    pub fn output(&self) -> C::Block {
        self.output
    }
}

impl<C: CipherCircuit> KeystreamBlock<C> {}

pub struct Encrypt<C: CipherCircuit> {
    keystream: Vec<KeystreamBlock<C>>,
}

pub struct DecryptPrivate<C: CipherCircuit> {
    keystream: Vec<KeystreamBlock<C>>,
    otps: Option<Vec<<<C as CipherCircuit>::Block as Repr<Binary>>::Clear>>,
}

pub struct DecryptPublic<C: CipherCircuit> {
    keystream: Vec<KeystreamBlock<C>>,
}
