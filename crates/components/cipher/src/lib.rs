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

#[derive(Debug, Clone)]
pub struct Keystream<C: CipherCircuit> {
    explicit_nonces: Vec<C::Nonce>,
    counters: Vec<C::Counter>,
    inputs: Vec<C::Block>,
    outputs: Vec<C::Block>,
}

impl<C: CipherCircuit> Keystream<C> {
    pub fn explicit_nonces(&self) -> &[<C as CipherCircuit>::Nonce] {
        &self.explicit_nonces
    }

    pub fn counters(&self) -> &[<C as CipherCircuit>::Counter] {
        &self.counters
    }

    pub fn inputs(&self) -> &[<C as CipherCircuit>::Block] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[<C as CipherCircuit>::Block] {
        &self.outputs
    }

    pub fn chunk(&mut self, block_count: usize) -> Keystream<C> {
        let explicit_nonces = self.explicit_nonces.drain(..block_count).collect();
        let counters = self.counters.drain(..block_count).collect();
        let inputs = self.inputs.drain(..block_count).collect();
        let outputs = self.outputs.drain(..block_count).collect();

        Keystream {
            explicit_nonces,
            counters,
            inputs,
            outputs,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.explicit_nonces.len()
    }

    fn push(
        &mut self,
        explicit_nonce: C::Nonce,
        counter: C::Counter,
        input: C::Block,
        output: C::Block,
    ) {
        self.explicit_nonces.push(explicit_nonce);
        self.counters.push(counter);
        self.inputs.push(input);
        self.outputs.push(output);
    }

    fn append(&mut self, mut keystream: Keystream<C>) {
        self.explicit_nonces.append(&mut keystream.explicit_nonces);
        self.counters.append(&mut keystream.counters);
        self.inputs.append(&mut keystream.inputs);
        self.outputs.append(&mut keystream.outputs);
    }
}

impl<C: CipherCircuit> Default for Keystream<C> {
    fn default() -> Self {
        Self {
            explicit_nonces: Vec::default(),
            counters: Vec::default(),
            inputs: Vec::default(),
            outputs: Vec::default(),
        }
    }
}

pub struct Encrypt<C: CipherCircuit> {
    keystream: Keystream<C>,
}

pub struct DecryptPrivate<C: CipherCircuit> {
    keystream: Keystream<C>,
    otps: Option<Vec<<<C as CipherCircuit>::Block as Repr<Binary>>::Clear>>,
}

pub struct DecryptPublic<C: CipherCircuit> {
    keystream: Keystream<C>,
}
