use std::sync::Arc;

use mpc_circuits::{Circuit, Input};
use tls_2pc_core::{AES_CTR, AES_CTR_MASKED};

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

    const IS_REVERSED: bool;

    /// Returns circuit
    fn circuit(&self) -> Arc<Circuit>;
    /// Returns input corresponding to key
    fn key(&self) -> Input;
    /// Returns input corresponding to IV
    fn iv(&self) -> Input;
    /// Returns input corresponding to text
    fn text(&self) -> Input;
    /// Returns input corresponding to nonce
    fn nonce(&self) -> Input;
    /// Returns input corresponding to counter
    fn counter(&self) -> Input;
}

pub trait CtrShareCircuit: Default + Clone + Send + Sync {
    const KEY_SIZE: usize;
    const IV_SIZE: usize;
    const BLOCK_SIZE: usize;
    const NONCE_SIZE: usize;

    const IS_REVERSED: bool;

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

    const IS_REVERSED: bool = true;

    fn circuit(&self) -> Arc<Circuit> {
        AES_CTR.clone()
    }

    fn key(&self) -> Input {
        AES_CTR.input(0).expect("AES_CTR input 0 should be key")
    }

    fn iv(&self) -> Input {
        AES_CTR.input(1).expect("AES_CTR input 1 should be IV")
    }

    fn text(&self) -> Input {
        AES_CTR.input(2).expect("AES_CTR input 2 should be block")
    }

    fn nonce(&self) -> Input {
        AES_CTR.input(3).expect("AES_CTR input 3 should be nonce")
    }

    fn counter(&self) -> Input {
        AES_CTR.input(4).expect("AES_CTR input 4 should be counter")
    }
}

impl CtrShareCircuit for Aes128CtrMaskedCircuit {
    const KEY_SIZE: usize = 16;
    const IV_SIZE: usize = 4;
    const BLOCK_SIZE: usize = 16;
    const NONCE_SIZE: usize = 8;

    const IS_REVERSED: bool = true;

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
