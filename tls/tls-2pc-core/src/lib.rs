pub mod msgs;
#[cfg(feature = "prf")]
pub mod prf;

pub use mpc_circuits::{Circuit, CircuitError};

use once_cell::sync::Lazy;
use std::sync::Arc;

#[cfg(feature = "c1")]
pub static CIRCUIT_1_BYTES: &[u8] = std::include_bytes!("../circuits/bin/c1.bin");
#[cfg(feature = "c2")]
pub static CIRCUIT_2_BYTES: &[u8] = std::include_bytes!("../circuits/bin/c2.bin");
#[cfg(feature = "c3")]
pub static CIRCUIT_3_BYTES: &[u8] = std::include_bytes!("../circuits/bin/c3.bin");
#[cfg(feature = "c4")]
pub static CIRCUIT_4_BYTES: &[u8] = std::include_bytes!("../circuits/bin/c4.bin");
#[cfg(feature = "c5")]
pub static CIRCUIT_5_BYTES: &[u8] = std::include_bytes!("../circuits/bin/c5.bin");
#[cfg(feature = "c6")]
pub static CIRCUIT_6_BYTES: &[u8] = std::include_bytes!("../circuits/bin/c6.bin");
#[cfg(feature = "c7")]
pub static CIRCUIT_7_BYTES: &[u8] = std::include_bytes!("../circuits/bin/c7.bin");
#[cfg(feature = "aes")]
pub static AES_BYTES: &[u8] = mpc_circuits::AES_128_REVERSE;
#[cfg(feature = "aes_masked")]
pub static AES_MASKED_BYTES: &[u8] = std::include_bytes!("../circuits/bin/aes_masked.bin");
#[cfg(feature = "aes_ctr")]
pub static AES_CTR_BYTES: &[u8] = std::include_bytes!("../circuits/bin/aes_ctr.bin");
#[cfg(feature = "aes_ctr_masked")]
pub static AES_CTR_MASKED_BYTES: &[u8] = std::include_bytes!("../circuits/bin/aes_ctr_masked.bin");

#[cfg(feature = "c1")]
pub static CIRCUIT_1: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(CIRCUIT_1_BYTES).unwrap());
#[cfg(feature = "c2")]
pub static CIRCUIT_2: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(CIRCUIT_2_BYTES).unwrap());
#[cfg(feature = "c3")]
pub static CIRCUIT_3: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(CIRCUIT_3_BYTES).unwrap());
#[cfg(feature = "c4")]
pub static CIRCUIT_4: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(CIRCUIT_4_BYTES).unwrap());
#[cfg(feature = "c5")]
pub static CIRCUIT_5: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(CIRCUIT_5_BYTES).unwrap());
#[cfg(feature = "c6")]
pub static CIRCUIT_6: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(CIRCUIT_6_BYTES).unwrap());
#[cfg(feature = "c7")]
pub static CIRCUIT_7: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(CIRCUIT_7_BYTES).unwrap());
#[cfg(feature = "aes")]
pub static AES: Lazy<Arc<Circuit>> = Lazy::new(|| Circuit::load_bytes(AES_BYTES).unwrap());
#[cfg(feature = "aes_masked")]
pub static AES_MASKED: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(AES_MASKED_BYTES).unwrap());
#[cfg(feature = "aes_ctr")]
pub static AES_CTR: Lazy<Arc<Circuit>> = Lazy::new(|| Circuit::load_bytes(AES_CTR_BYTES).unwrap());
#[cfg(feature = "aes_ctr_masked")]
pub static AES_CTR_MASKED: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(AES_CTR_MASKED_BYTES).unwrap());

pub struct SessionKeyShares {
    cwk: [u8; 16],
    swk: [u8; 16],
    civ: [u8; 4],
    siv: [u8; 4],
}

impl SessionKeyShares {
    /// Creates new SessionKeyShares
    pub fn new(cwk: [u8; 16], swk: [u8; 16], civ: [u8; 4], siv: [u8; 4]) -> Self {
        Self { cwk, swk, civ, siv }
    }

    /// Returns client_write_key share
    pub fn cwk(&self) -> [u8; 16] {
        self.cwk
    }

    /// Returns server_write_key share
    pub fn swk(&self) -> [u8; 16] {
        self.swk
    }

    /// Returns client IV share
    pub fn civ(&self) -> [u8; 4] {
        self.civ
    }

    /// Returns server IV share
    pub fn siv(&self) -> [u8; 4] {
        self.siv
    }
}
