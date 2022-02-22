pub mod base;
pub mod errors;
pub mod extension;

pub use base::*;
pub use errors::*;
pub use extension::*;

use crate::Block;

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

pub type ChaChaAesOTSender = KosSender<ChaCha12Rng, Aes128>;
pub type ChaChaAesOTReceiver = KosReceiver<ChaCha12Rng, Aes128>;

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

pub trait OTSender {
    fn base_setup(
        &mut self,
        base_sender_setup: BaseOTSenderSetup,
    ) -> Result<BaseOTReceiverSetup, OTSenderError>;

    fn base_receive_seeds(&mut self, send: BaseOTSenderSend) -> Result<(), OTSenderError>;

    fn extension_setup(&mut self, receiver_setup: OTReceiverSetup) -> Result<(), OTSenderError>;

    fn send(&mut self, inputs: &[[Block; 2]]) -> Result<OTSenderSend, OTSenderError>;
}

pub trait OTReceiver {
    fn base_setup(&mut self) -> Result<BaseOTSenderSetup, OTReceiverError>;

    fn base_send_seeds(
        &mut self,
        base_receiver_setup: BaseOTReceiverSetup,
    ) -> Result<BaseOTSenderSend, OTReceiverError>;

    fn extension_setup(&mut self, choice: &[bool]) -> Result<OTReceiverSetup, OTReceiverError>;

    fn receive(
        &mut self,
        choice: &[bool],
        send: OTSenderSend,
    ) -> Result<OTReceiverReceive, OTReceiverError>;
}
