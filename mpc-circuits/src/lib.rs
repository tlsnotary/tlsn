pub mod circuit;
mod error;
pub mod parse;
pub mod proto;

pub use circuit::{Circuit, Gate, Group, Input, Output};
pub use error::Error;

#[cfg(feature = "aes_128_reverse")]
pub static AES_128_REVERSE: &'static [u8] =
    std::include_bytes!("../circuits/protobuf/aes_128_reverse.bin");

#[cfg(feature = "aes_128")]
pub static AES_128: &'static [u8] = std::include_bytes!("../circuits/protobuf/aes_128.bin");

#[cfg(feature = "adder64")]
pub static ADDER_64: &'static [u8] = std::include_bytes!("../circuits/protobuf/adder64.bin");
