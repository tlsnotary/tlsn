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

pub type ChaChaAesOTSender = OTSender<ChaCha12Rng, Aes128>;
pub type ChaChaAesOTReceiver = OTReceiver<ChaCha12Rng, Aes128>;

impl Default for ChaChaAesOTSender {
    fn default() -> Self {
        let rng = ChaCha12Rng::from_entropy();
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        Self::new(rng, cipher)
    }
}

impl Default for ChaChaAesOTReceiver {
    fn default() -> Self {
        let rng = ChaCha12Rng::from_entropy();
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        Self::new(rng, cipher)
    }
}
