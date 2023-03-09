use std::sync::Arc;

use cipher_circuits::{AES_CTR, AES_CTR_MASKED};
use mpc_circuits::{Circuit, Input, Output};

pub trait CtrCircuitSuite: Default + Clone + Send + Sync {
    type CtrCircuit: CtrCircuit;
    type CtrShareCircuit: CtrShareCircuit;

    const KEY_SIZE: usize;
    const IV_SIZE: usize;
    const BLOCK_SIZE: usize;
    const NONCE_SIZE: usize;
}

pub trait CtrCircuit: Default + Clone + Send + Sync {
    const KEY_SIZE: usize;
    const IV_SIZE: usize;
    const BLOCK_SIZE: usize;
    const NONCE_SIZE: usize;

    /// Returns circuit
    fn circuit(&self) -> Arc<Circuit>;
    /// Returns input corresponding to key
    fn key(&self) -> Input;
    /// Returns input corresponding to IV
    fn iv(&self) -> Input;
    /// Returns input corresponding to text
    fn input_text(&self) -> Input;
    /// Returns input corresponding to nonce
    fn nonce(&self) -> Input;
    /// Returns input corresponding to counter
    fn counter(&self) -> Input;
    /// Returns output corresponding to output text
    fn output_text(&self) -> Output;
}

pub trait CtrShareCircuit: Default + Clone + Send + Sync {
    const KEY_SIZE: usize;
    const IV_SIZE: usize;
    const BLOCK_SIZE: usize;
    const NONCE_SIZE: usize;

    /// Returns circuit
    fn circuit(&self) -> Arc<Circuit>;
    /// Returns input corresponding to key
    fn key(&self) -> Input;
    /// Returns input corresponding to IV
    fn iv(&self) -> Input;
    /// Returns input corresponding to nonce
    fn nonce(&self) -> Input;
    /// Returns input corresponding to counter
    fn counter(&self) -> Input;
    /// Returns input corresponding to mask 0
    fn mask_0(&self) -> Input;
    /// Returns input corresponding to mask 1
    fn mask_1(&self) -> Input;
}

#[derive(Default, Debug, Clone)]
pub struct Aes128Ctr;

#[derive(Default, Debug, Clone)]
pub struct Aes128CtrCircuit;

#[derive(Default, Debug, Clone)]
pub struct Aes128CtrMaskedCircuit;

impl CtrCircuitSuite for Aes128Ctr {
    type CtrCircuit = Aes128CtrCircuit;
    type CtrShareCircuit = Aes128CtrMaskedCircuit;

    const KEY_SIZE: usize = 16;
    const IV_SIZE: usize = 4;
    const BLOCK_SIZE: usize = 16;
    const NONCE_SIZE: usize = 8;
}

impl CtrCircuit for Aes128CtrCircuit {
    const KEY_SIZE: usize = 16;
    const IV_SIZE: usize = 4;
    const BLOCK_SIZE: usize = 16;
    const NONCE_SIZE: usize = 8;

    fn circuit(&self) -> Arc<Circuit> {
        AES_CTR.clone()
    }

    fn key(&self) -> Input {
        AES_CTR.input(0).expect("AES_CTR input 0 should be key")
    }

    fn iv(&self) -> Input {
        AES_CTR.input(1).expect("AES_CTR input 1 should be IV")
    }

    fn input_text(&self) -> Input {
        AES_CTR.input(2).expect("AES_CTR input 2 should be block")
    }

    fn nonce(&self) -> Input {
        AES_CTR.input(3).expect("AES_CTR input 3 should be nonce")
    }

    fn counter(&self) -> Input {
        AES_CTR.input(4).expect("AES_CTR input 4 should be counter")
    }

    fn output_text(&self) -> Output {
        AES_CTR
            .output(0)
            .expect("AES_CTR output 0 should be output text")
    }
}

impl CtrShareCircuit for Aes128CtrMaskedCircuit {
    const KEY_SIZE: usize = 16;
    const IV_SIZE: usize = 4;
    const BLOCK_SIZE: usize = 16;
    const NONCE_SIZE: usize = 8;

    fn circuit(&self) -> Arc<Circuit> {
        AES_CTR_MASKED.clone()
    }

    fn key(&self) -> Input {
        AES_CTR_MASKED
            .input(0)
            .expect("AES_CTR_MASKED input 0 should be key")
    }

    fn iv(&self) -> Input {
        AES_CTR_MASKED
            .input(1)
            .expect("AES_CTR_MASKED input 1 should be IV")
    }

    fn nonce(&self) -> Input {
        AES_CTR_MASKED
            .input(2)
            .expect("AES_CTR_MASKED input 2 should be nonce")
    }

    fn counter(&self) -> Input {
        AES_CTR_MASKED
            .input(3)
            .expect("AES_CTR_MASKED input 3 should be counter")
    }

    fn mask_0(&self) -> Input {
        AES_CTR_MASKED
            .input(4)
            .expect("AES_CTR_MASKED input 4 should be mask_0")
    }

    fn mask_1(&self) -> Input {
        AES_CTR_MASKED
            .input(5)
            .expect("AES_CTR_MASKED input 5 should be mask_1")
    }
}
