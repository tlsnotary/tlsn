use std::sync::Arc;

use cipher_circuits::AES_MASKED;
use mpc_circuits::{Circuit, Input, Output, AES_128};

pub trait BlockCipherCircuitSuite: Default + Clone + Send + Sync {
    type BlockCipherCircuit: BlockCipherCircuit;
    type ShareCircuit: BlockCipherShareCircuit;

    const KEY_SIZE: usize;
    const BLOCK_SIZE: usize;
}

pub trait BlockCipherCircuit: Default + Clone + Send + Sync {
    const KEY_SIZE: usize;
    const BLOCK_SIZE: usize;

    /// Returns circuit
    fn circuit(&self) -> Arc<Circuit>;
    /// Returns input corresponding to key
    fn key(&self) -> Input;
    /// Returns input corresponding to text
    fn text(&self) -> Input;
    /// Returns output corresponding to ciphertext
    fn ciphertext(&self) -> Output;
}

pub trait BlockCipherShareCircuit: Default + Clone + Send + Sync {
    const KEY_SIZE: usize;
    const BLOCK_SIZE: usize;

    /// Returns circuit
    fn circuit(&self) -> Arc<Circuit>;
    /// Returns input corresponding to key
    fn key(&self) -> Input;
    /// Returns input corresponding to text
    fn text(&self) -> Input;
    /// Returns input corresponding to mask 0
    fn mask_0(&self) -> Input;
    /// Returns input corresponding to mask 1
    fn mask_1(&self) -> Input;
    /// Returns output corresponding to masked ciphertext
    fn masked_ciphertext(&self) -> Output;
}

#[derive(Default, Debug, Clone)]
pub struct Aes128;

impl BlockCipherCircuitSuite for Aes128 {
    type BlockCipherCircuit = Aes128Circuit;
    type ShareCircuit = Aes128ShareCircuit;

    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;
}

#[derive(Default, Debug, Clone)]
pub struct Aes128Circuit;

#[derive(Default, Debug, Clone)]
pub struct Aes128ShareCircuit;

impl BlockCipherCircuit for Aes128Circuit {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;

    fn circuit(&self) -> Arc<Circuit> {
        AES_128.clone()
    }

    fn key(&self) -> Input {
        AES_128.input(0).expect("AES input 0 should be key")
    }

    fn text(&self) -> Input {
        AES_128.input(1).expect("AES input 1 should be text")
    }

    fn ciphertext(&self) -> Output {
        AES_128
            .output(0)
            .expect("AES output 0 should be ciphertext")
    }
}

impl BlockCipherShareCircuit for Aes128ShareCircuit {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;

    fn circuit(&self) -> Arc<Circuit> {
        AES_MASKED.clone()
    }

    fn key(&self) -> Input {
        AES_MASKED.input(0).expect("AES input 0 should be key")
    }

    fn text(&self) -> Input {
        AES_MASKED.input(1).expect("AES input 1 should be text")
    }

    fn mask_0(&self) -> Input {
        AES_MASKED.input(2).expect("AES input 2 should be mask 0")
    }

    fn mask_1(&self) -> Input {
        AES_MASKED.input(3).expect("AES input 3 should be mask 1")
    }

    fn masked_ciphertext(&self) -> Output {
        AES_MASKED
            .output(0)
            .expect("AES output 0 should be masked ciphertext")
    }
}
