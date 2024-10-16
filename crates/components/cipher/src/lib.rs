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

use std::collections::VecDeque;

use async_trait::async_trait;
use cipher::CipherCircuit;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;

#[async_trait]
pub trait Cipher<C: CipherCircuit, Ctx: Context, V: Vm<Binary>> {
    /// The error type for the cipher.
    type Error: std::error::Error + Send + Sync + 'static;

    fn set_key(&mut self, key: <C as CipherCircuit>::Key);

    fn set_iv(&mut self, iv: <C as CipherCircuit>::Iv);

    fn alloc(&mut self, vm: &mut V, block_count: usize) -> Result<Keystream<C>, Self::Error>;

    fn alloc_block(&mut self, vm: &mut V) -> Result<EcbBlock<C>, Self::Error>;
}

pub struct Keystream<C: CipherCircuit> {
    key: <C as CipherCircuit>::Key,
    iv: <C as CipherCircuit>::Iv,
    explicit_nonces: VecDeque<C::Nonce>,
    counters: VecDeque<C::Counter>,
    outputs: VecDeque<C::Block>,
}

impl<C: CipherCircuit> Keystream<C> {
    pub(crate) fn new(key: <C as CipherCircuit>::Key, iv: <C as CipherCircuit>::Iv) -> Self {
        Self {
            key,
            iv,
            explicit_nonces: VecDeque::default(),
            counters: VecDeque::default(),
            outputs: VecDeque::default(),
        }
    }

    pub fn chunk(&mut self, block_count: usize) -> Keystream<C> {
        let explicit_nonces = self.explicit_nonces.drain(..block_count).collect();
        let counters = self.counters.drain(..block_count).collect();
        let outputs = self.outputs.drain(..block_count).collect();

        Keystream {
            key: self.key,
            iv: self.iv,
            explicit_nonces,
            counters,
            outputs,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.explicit_nonces.len()
    }

    fn push(&mut self, explicit_nonce: C::Nonce, counter: C::Counter, output: C::Block) {
        self.explicit_nonces.push_back(explicit_nonce);
        self.counters.push_back(counter);
        self.outputs.push_back(output);
    }

    fn append(&mut self, mut keystream: Keystream<C>) {
        self.explicit_nonces.append(&mut keystream.explicit_nonces);
        self.counters.append(&mut keystream.counters);
        self.outputs.append(&mut keystream.outputs);
    }
}

// TODO
pub struct EcbBlock<C> {
    pd: std::marker::PhantomData<C>,
}

#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct KeystreamError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl KeystreamError {
    pub(crate) fn new<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            source: source.into(),
        }
    }
}
