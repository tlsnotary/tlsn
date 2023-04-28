use std::sync::Arc;

use mpc_circuits::{
    types::{StaticValueType, Value},
    Circuit,
};

use crate::circuit::AES_CTR;

/// A counter-mode block cipher circuit.
pub trait CtrCircuit: Default + Clone + Send + Sync + 'static {
    /// The key type
    type KEY: StaticValueType + Send + Sync + 'static;
    /// The block type
    type BLOCK: StaticValueType
        + TryFrom<Vec<u8>>
        + TryFrom<Value>
        + Into<Vec<u8>>
        + Default
        + Send
        + Sync
        + 'static;
    /// The IV type
    type IV: StaticValueType
        + TryFrom<Vec<u8>>
        + TryFrom<Value>
        + Into<Vec<u8>>
        + Send
        + Sync
        + 'static;
    /// The nonce type
    type NONCE: StaticValueType
        + TryFrom<Vec<u8>>
        + TryFrom<Value>
        + Into<Vec<u8>>
        + Clone
        + Copy
        + Send
        + Sync
        + 'static;

    /// The length of the key
    const KEY_LEN: usize;
    /// The length of the block
    const BLOCK_LEN: usize;
    /// The length of the IV
    const IV_LEN: usize;
    /// The length of the nonce
    const NONCE_LEN: usize;

    /// Returns circuit
    fn circuit() -> Arc<Circuit>;
}

/// A circuit for AES-128 in counter mode.
#[derive(Default, Debug, Clone)]
pub struct Aes128Ctr;

impl CtrCircuit for Aes128Ctr {
    type KEY = [u8; 16];
    type BLOCK = [u8; 16];
    type IV = [u8; 4];
    type NONCE = [u8; 8];

    const KEY_LEN: usize = 16;
    const BLOCK_LEN: usize = 16;
    const IV_LEN: usize = 4;
    const NONCE_LEN: usize = 8;

    fn circuit() -> Arc<Circuit> {
        AES_CTR.clone()
    }
}
