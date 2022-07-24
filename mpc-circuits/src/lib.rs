pub mod circuit;
mod error;
mod gate;
pub mod parse;
pub mod proto;

pub use circuit::{Circuit, CircuitDescription};
pub use error::Error;
pub use gate::Gate;

use once_cell::sync::Lazy;

#[cfg(feature = "aes_128_reverse")]
pub static AES_128_REVERSE: Lazy<Circuit> = Lazy::new(|| {
    let bytes = std::include_bytes!("../circuits/protobuf/aes_128_reverse.bin");
    Circuit::load_bytes(bytes).unwrap()
});

#[cfg(feature = "aes_128")]
pub static AES_128: Lazy<Circuit> = Lazy::new(|| {
    let bytes = std::include_bytes!("../circuits/protobuf/aes_128.bin");
    Circuit::load_bytes(bytes).unwrap()
});

#[cfg(feature = "adder64")]
pub static ADDER_64: Lazy<Circuit> = Lazy::new(|| {
    let bytes = std::include_bytes!("../circuits/protobuf/adder64.bin");
    Circuit::load_bytes(bytes).unwrap()
});
