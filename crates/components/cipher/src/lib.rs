//! This crate provides implementations of 2PC ciphers for encryption with a
//! shared key.
//!
//! Both parties can work together to encrypt and decrypt messages with
//! different visibility configurations. See [`Cipher`] and [`Keystream`] for
//! more information on the interface.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod aes;
mod circuit;

use async_trait::async_trait;
use circuit::build_xor_circuit;
use mpz_circuits::types::ValueType;
use mpz_memory_core::{
    FromRaw, MemoryExt, Repr, Slice, StaticSize, ToRaw, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{CallBuilder, CallError, Vm, prelude::*};
use std::collections::VecDeque;

/// Provides computation of 2PC ciphers in counter and ECB mode.
///
/// After setting `key` and `iv` allows to compute the keystream via
/// [`Cipher::alloc`] or a single block in ECB mode via
/// [`Cipher::assign_block`]. [`Keystream`] provides more tooling to compute the
/// final cipher output in counter mode.
#[async_trait]
pub trait Cipher {
    /// The error type for the cipher.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Cipher key.
    type Key;
    /// Cipher IV.
    type Iv;
    /// Cipher nonce.
    type Nonce;
    /// Cipher counter.
    type Counter;
    /// Cipher block.
    type Block;

    /// Sets the key.
    fn set_key(&mut self, key: Self::Key);

    /// Sets the initialization vector.
    fn set_iv(&mut self, iv: Self::Iv);

    /// Returns the key reference.
    fn key(&self) -> Option<&Self::Key>;

    /// Returns the iv reference.
    fn iv(&self) -> Option<&Self::Iv>;

    /// Allocates a single block in ECB mode.
    fn alloc_block(
        &self,
        vm: &mut dyn Vm<Binary>,
        input: Self::Block,
    ) -> Result<Self::Block, Self::Error>;

    /// Allocates a single block in counter mode.
    #[allow(clippy::type_complexity)]
    fn alloc_ctr_block(
        &self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<CtrBlock<Self::Nonce, Self::Counter, Self::Block>, Self::Error>;

    /// Allocates a keystream in counter mode.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine to allocate into.
    /// * `len` - Length of the stream in bytes.
    #[allow(clippy::type_complexity)]
    fn alloc_keystream(
        &self,
        vm: &mut dyn Vm<Binary>,
        len: usize,
    ) -> Result<Keystream<Self::Nonce, Self::Counter, Self::Block>, Self::Error>;
}

/// A block in counter mode.
#[derive(Debug, Clone, Copy)]
pub struct CtrBlock<N, C, O> {
    /// Explicit nonce reference.
    pub explicit_nonce: N,
    /// Counter reference.
    pub counter: C,
    /// Output reference.
    pub output: O,
}

/// The keystream of the cipher.
///
/// Can be used to XOR with the cipher input to operate the cipher in counter
/// mode.
pub struct Keystream<N, C, O> {
    blocks: VecDeque<CtrBlock<N, C, O>>,
}

impl<N, C, O> Default for Keystream<N, C, O> {
    fn default() -> Self {
        Self {
            blocks: VecDeque::new(),
        }
    }
}

impl<N, C, O> Keystream<N, C, O>
where
    N: Repr<Binary> + StaticSize<Binary> + Copy,
    C: Repr<Binary> + StaticSize<Binary> + Copy,
    O: Repr<Binary> + StaticSize<Binary> + Copy,
{
    /// Creates a new keystream from the provided blocks.
    ///
    /// # Panics
    ///
    /// * If the output of the keystream is not ordered and contiguous in
    ///   memory.
    pub fn new(blocks: &[CtrBlock<N, C, O>]) -> Self {
        let mut pos = blocks
            .first()
            .map(|block| block.output.to_raw().ptr().as_usize())
            .unwrap_or(0);

        for block in blocks {
            if block.output.to_raw().ptr().as_usize() != pos {
                panic!("output of keystream blocks must be ordered and contiguous in memory");
            }

            pos += O::SIZE;
        }

        Self {
            blocks: VecDeque::from_iter(blocks.iter().copied()),
        }
    }

    /// Consumes keystream material.
    ///
    /// Returns the consumed keystream material, leaving the remaining material
    /// in place.
    ///
    /// # Arguments
    ///
    /// * `len` - Length of the keystream in bytes to return.
    pub fn consume(&mut self, len: usize) -> Result<Self, CipherError> {
        let block_count = len.div_ceil(self.block_size());

        if block_count > self.blocks.len() {
            return Err(CipherError::new("insufficient keystream"));
        }

        let blocks = self.blocks.split_off(self.blocks.len() - block_count);

        Ok(Self { blocks })
    }

    /// Applies the keystream to the provided input.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `input` - Input data.
    pub fn apply(
        &self,
        vm: &mut dyn Vm<Binary>,
        input: Vector<U8>,
    ) -> Result<Vector<U8>, CipherError> {
        if input.len() != self.len() {
            return Err(CipherError::new("input length must match keystream length"));
        } else if self.blocks.is_empty() {
            return Err(CipherError::new("no keystream material available"));
        }

        let xor = build_xor_circuit(&[ValueType::new_array::<u8>(self.block_size())]);
        let mut pos = 0;
        let mut outputs = Vec::with_capacity(self.blocks.len());
        for block in &self.blocks {
            let call = CallBuilder::new(xor.clone())
                .arg(block.output)
                .arg(
                    input
                        .get(pos..pos + self.block_size())
                        .expect("input length was checked"),
                )
                .build()?;
            let output: Vector<U8> = vm.call(call).map_err(CipherError::new)?;
            outputs.push(output);
            pos += self.block_size();
        }

        // Calls were performed contiguously, so the output data is contiguous.
        let ptr = outputs
            .first()
            .map(|output| output.to_raw().ptr())
            .expect("keystream is not empty");
        let size = self.blocks.len() * O::SIZE;

        let output = Vector::<U8>::from_raw(Slice::new_unchecked(ptr, size));

        Ok(output)
    }

    /// Returns `len` bytes of the keystream as a vector.
    pub fn to_vector(&self, len: usize) -> Result<Vector<U8>, CipherError> {
        if len == 0 {
            return Err(CipherError::new("length must be greater than 0"));
        } else if self.blocks.is_empty() {
            return Err(CipherError::new("no keystream material available"));
        }

        let block_count = len.div_ceil(self.block_size());
        if block_count != self.blocks.len() {
            return Err(CipherError::new("length does not match keystream length"));
        }

        let ptr = self
            .blocks
            .front()
            .map(|block| block.output.to_raw().ptr())
            .expect("block count should be greater than 0");
        let size = block_count * O::SIZE;

        let mut keystream = Vector::<U8>::from_raw(Slice::new_unchecked(ptr, size));
        keystream.truncate(len);

        Ok(keystream)
    }

    /// Assigns the keystream inputs.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `ctr` - Counter function. The provided function will be called to
    ///   assign the counter values for each block.
    pub fn assign(
        &self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: N::Clear,
        mut ctr: impl FnMut() -> C::Clear,
    ) -> Result<(), CipherError>
    where
        N::Clear: Copy,
        C::Clear: Copy,
    {
        for block in &self.blocks {
            vm.assign(block.explicit_nonce, explicit_nonce)
                .map_err(CipherError::new)?;
            vm.commit(block.explicit_nonce).map_err(CipherError::new)?;
            vm.assign(block.counter, ctr()).map_err(CipherError::new)?;
            vm.commit(block.counter).map_err(CipherError::new)?;
        }

        Ok(())
    }

    /// Returns the block size in bytes.
    fn block_size(&self) -> usize {
        O::SIZE / 8
    }

    /// Returns the length of the keystream in bytes.
    fn len(&self) -> usize {
        self.block_size() * self.blocks.len()
    }
}

/// A cipher error.
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
