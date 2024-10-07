//! Ciphers and circuits.

use mpz_circuits::{
    circuits::{aes128_trace, AES128},
    once_cell::sync::Lazy,
    Circuit, CircuitBuilder,
};
use mpz_memory_core::{Array, StaticSize};
use std::sync::Arc;

use crate::mock::U8;

/// A cipher circuit.
pub trait Cipher: Default {
    /// The key type.
    type Key: StaticSize;
    /// The block type.
    type Block: StaticSize;

    /// Returns the circuit of the cipher.
    fn circuit() -> Arc<Circuit>;

    /// Returns the circuit of the cipher in counter mode.
    fn ctr_circuit() -> Arc<Circuit>;
}

/// A circuit for AES-128.
#[derive(Default, Debug, Clone, Copy)]
pub struct Aes128;

impl Cipher for Aes128 {
    type Key = Array<U8, 16>;
    type Block = Array<U8, 16>;

    /// `fn(key: [u8; 16], msg: [u8; 16]) -> [u8; 16]`
    fn circuit() -> Arc<Circuit> {
        AES128.clone()
    }

    /// `fn(key: [u8; 16], block: [u8; 16], message: [u8; 16]) -> [u8; 16]`
    fn ctr_circuit() -> Arc<Circuit> {
        AES128_CTR.clone()
    }
}

static AES128_CTR: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let builder = CircuitBuilder::new();

    let key = builder.add_array_input::<u8, 16>();
    let block = builder.add_array_input::<u8, 16>();
    let keystream = aes128_trace(builder.state(), key, block);

    let message = builder.add_array_input::<u8, 16>();
    let output = keystream
        .into_iter()
        .zip(message)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();
    builder.add_output(output);

    Arc::new(builder.build().unwrap())
});
