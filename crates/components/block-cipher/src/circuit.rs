use std::sync::Arc;

use mpz_circuits::{
    circuits::AES128,
    types::{StaticValueType, Value},
    Circuit,
};

/// A block cipher circuit.
pub trait BlockCipherCircuit: Default + Clone + Send + Sync {
    /// The key type.
    type KEY: StaticValueType + Send + Sync;
    /// The block type.
    type BLOCK: StaticValueType + TryFrom<Vec<u8>> + TryFrom<Value> + Into<Vec<u8>> + Send + Sync;

    /// The length of the key.
    const KEY_LEN: usize;
    /// The length of the block.
    const BLOCK_LEN: usize;

    /// Returns the circuit of the cipher.
    fn circuit() -> Arc<Circuit>;
}

/// Aes128 block cipher circuit.
#[derive(Default, Debug, Clone)]
pub struct Aes128;

impl BlockCipherCircuit for Aes128 {
    type KEY = [u8; 16];
    type BLOCK = [u8; 16];

    const KEY_LEN: usize = 16;
    const BLOCK_LEN: usize = 16;

    fn circuit() -> Arc<Circuit> {
        AES128.clone()
    }
}
