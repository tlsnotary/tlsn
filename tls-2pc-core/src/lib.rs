#[cfg(feature = "ghash")]
pub mod ghash;
pub mod msgs;
#[cfg(feature = "prf")]
pub mod prf;

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
