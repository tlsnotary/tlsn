#[cfg(feature = "ghash")]
pub mod ghash;
pub mod msgs;
#[cfg(feature = "prf")]
pub mod prf;

pub use mpc_circuits::{Circuit, CircuitError};

#[cfg(feature = "c1")]
pub static CIRCUIT_1: &'static [u8] = std::include_bytes!("../circuits/bin/c1.bin");
#[cfg(feature = "c2")]
pub static CIRCUIT_2: &'static [u8] = std::include_bytes!("../circuits/bin/c2.bin");
#[cfg(feature = "c3")]
pub static CIRCUIT_3: &'static [u8] = std::include_bytes!("../circuits/bin/c3.bin");
#[cfg(feature = "c4")]
pub static CIRCUIT_4: &'static [u8] = std::include_bytes!("../circuits/bin/c4.bin");
#[cfg(feature = "c5")]
pub static CIRCUIT_5: &'static [u8] = std::include_bytes!("../circuits/bin/c5.bin");
#[cfg(feature = "c6")]
pub static CIRCUIT_6: &'static [u8] = std::include_bytes!("../circuits/bin/c6.bin");
#[cfg(feature = "c7")]
pub static CIRCUIT_7: &'static [u8] = std::include_bytes!("../circuits/bin/c7.bin");

pub struct SessionKeyShares {
    swk: [u8; 16],
    cwk: [u8; 16],
    siv: [u8; 4],
    civ: [u8; 4],
}

impl SessionKeyShares {
    /// Creates new SessionKeyShares
    pub fn new(swk: [u8; 16], cwk: [u8; 16], siv: [u8; 4], civ: [u8; 4]) -> Self {
        Self { swk, cwk, siv, civ }
    }

    /// Returns server_write_key share
    pub fn swk(&self) -> [u8; 16] {
        self.swk
    }

    /// Returns client_write_key share
    pub fn cwk(&self) -> [u8; 16] {
        self.cwk
    }

    /// Returns server IV share
    pub fn siv(&self) -> [u8; 4] {
        self.siv
    }

    /// Returns client IV share
    pub fn civ(&self) -> [u8; 4] {
        self.civ
    }
}
