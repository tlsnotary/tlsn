pub mod base;
pub mod errors;
pub mod extension;

pub use base::*;
pub use errors::*;
pub use extension::*;

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

pub fn default_sender() -> OTSender<ChaCha12Rng, Aes128> {
    let rng = ChaCha12Rng::from_entropy();
    let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    OTSender::new(rng, cipher)
}

pub fn default_receiver() -> OTReceiver<ChaCha12Rng, Aes128> {
    let rng = ChaCha12Rng::from_entropy();
    let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    OTReceiver::new(rng, cipher)
}
