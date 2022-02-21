pub mod errors;

use pop_mpc_core::ot::{OTReceiver as OTr, OTSender as OTs};
use errors::*;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use aes::{BlockCipher, BlockEncrypt};

pub struct AsyncOTSender<R, C> {
    ot: OTs<R,C>,
    setup: bool
}

pub struct AsyncOTReceiver<R, C> {
    ot: OTr<R,C>,
    setup: bool
}

impl<R: Rng + CryptoRng + SeedableRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt> AsyncOTSender<R, C> {
    pub fn new(rng: R, cipher: C) -> {
        let ot = OTs::new(rng, cipher);
    }
}

impl<R: Rng + CryptoRng + SeedableRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt> AsyncOTReceiver<R, C> {
    pub fn new(rng: R, cipher: C) -> Self {
        let ot = OTr::new(rng, cipher);
        Self { ot, setup: false }
    }

    pub async fn setup(&mut self) -> Result<(), AsyncOTSenderError> {

    }

    pub async fn send(&mut self, inputs:&[[Block; 2]]) -> Result<(), AsyncOTSenderError> {
        
    }
}

#[cfg(tests)]
mod tests {

}