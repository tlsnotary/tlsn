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
pub mod circuit;
pub mod config;

use std::collections::VecDeque;

use async_trait::async_trait;
use circuit::CipherCircuit;
use mpz_circuits::types::{ValueType, U8};
use mpz_common::Context;
use mpz_memory_core::{binary::Binary, Vector};
use mpz_vm_core::{CallBuilder, Vm};

use self::circuit::build_xor_circuit;

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

    pub fn apply<V>(
        &mut self,
        vm: &mut V,
        input: Vector<U8>,
    ) -> Result<CipherOutput<C>, KeystreamError>
    where
        V: Vm<Binary>,
    {
        let xor = build_xor_circuit(&[ValueType::new_array::<u8>(input.len())]);
        //let output = CallBuilder::new(xor).arg(arg);
        todo!()
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
}

// TODO
pub struct CipherOutput<C> {
    pd: std::marker::PhantomData<C>,
}

impl<C: CipherCircuit> CipherOutput<C> {
    pub fn assign<V>(
        self,
        vm: V,
        nonce: [u8; 8],
        start_ctr: u32,
        message: Vec<u8>,
    ) -> Result<Vector<U8>, KeystreamError>
    where
        V: Vm<Binary>,
    {
        todo!()
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
