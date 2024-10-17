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
use circuit::{build_xor_circuit, CipherCircuit};
use mpz_circuits::types::ValueType;
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    FromRaw, Slice, StaticSize, ToRaw, Vector,
};
use mpz_vm_core::{CallBuilder, CallError, Vm, VmExt};

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
    pub(crate) explicit_nonces: VecDeque<C::Nonce>,
    pub(crate) counters: VecDeque<C::Counter>,
    pub(crate) outputs: VecDeque<C::Block>,
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

    pub fn apply<V>(self, vm: &mut V, input: Vector<U8>) -> Result<CipherOutput<C>, CipherError>
    where
        V: Vm<Binary>,
    {
        if self.block_len() * <C::Block as StaticSize<Binary>>::SIZE < input.len() {
            return Err(CipherError::new("input is too long for keystream"));
        }

        let mut keystream: Vector<U8> = transmute(self.outputs);
        keystream.truncate(input.len());

        let xor = build_xor_circuit(&[ValueType::new_array::<u8>(input.len())]);
        let call = CallBuilder::new(xor).arg(keystream).arg(input).build()?;

        let output: Vector<U8> = vm.call(call).map_err(CipherError::new)?;

        let cipher_output = CipherOutput {
            explicit_nonces: self.explicit_nonces,
            counters: self.counters,
            input,
            output,
        };

        Ok(cipher_output)
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
    pub fn block_len(&self) -> usize {
        self.explicit_nonces.len()
    }
}

pub struct CipherOutput<C: CipherCircuit> {
    pub(crate) explicit_nonces: VecDeque<C::Nonce>,
    pub(crate) counters: VecDeque<C::Counter>,
    pub(crate) input: Vector<U8>,
    pub(crate) output: Vector<U8>,
}

impl<C: CipherCircuit> CipherOutput<C> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.input.len()
    }
}

// TODO
pub struct EcbBlock<C: CipherCircuit> {
    pd: std::marker::PhantomData<C>,
}

#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct CipherError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl CipherError {
    pub(crate) fn new<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            source: source.into(),
        }
    }
}

impl From<CallError> for CipherError {
    fn from(value: CallError) -> Self {
        Self::new(value)
    }
}

// # Safety

// This is only safe to call, if the provided vm arrays have been sequentially allocated.
fn transmute<T>(values: VecDeque<T>) -> Vector<U8>
where
    T: StaticSize<Binary> + ToRaw,
{
    let ptr = values
        .front()
        .expect("Vector should not be empty")
        .to_raw()
        .ptr();
    let size = <T as StaticSize<Binary>>::SIZE * values.len();
    let slice = Slice::new_unchecked(ptr, size);

    Vector::<U8>::from_raw(slice)
}
