pub mod base;
pub mod errors;
pub mod extension;

pub use base::*;
pub use errors::*;
pub use extension::*;

pub use crate::proto::ot::*;
use crate::Block;

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

pub type ChaChaAesOtSender = KosSender<ChaCha12Rng, Aes128>;
pub type ChaChaAesOtReceiver = KosReceiver<ChaCha12Rng, Aes128>;

impl Default for ChaChaAesOtSender {
    fn default() -> Self {
        let rng = ChaCha12Rng::from_entropy();
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        Self::new(rng, cipher)
    }
}

impl Default for ChaChaAesOtReceiver {
    fn default() -> Self {
        let rng = ChaCha12Rng::from_entropy();
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        Self::new(rng, cipher)
    }
}

pub trait OtSender {
    fn base_setup(
        &mut self,
        base_sender_setup: BaseOtSenderSetup,
    ) -> Result<BaseOtReceiverSetup, OtSenderError>;

    fn base_receive_seeds(&mut self, payload: BaseOtSenderPayload) -> Result<(), OtSenderError>;

    fn extension_setup(&mut self, receiver_setup: OtReceiverSetup) -> Result<(), OtSenderError>;

    fn send(&mut self, inputs: &[[Block; 2]]) -> Result<OtSenderPayload, OtSenderError>;
}

pub trait OtReceiver {
    fn base_setup(&mut self) -> Result<BaseOtSenderSetup, OtReceiverError>;

    fn base_send_seeds(
        &mut self,
        base_receiver_setup: BaseOtReceiverSetup,
    ) -> Result<BaseOtSenderPayload, OtReceiverError>;

    fn extension_setup(&mut self, choice: &[bool]) -> Result<OtReceiverSetup, OtReceiverError>;

    fn receive(
        &mut self,
        choice: &[bool],
        payload: OtSenderPayload,
    ) -> Result<Vec<Block>, OtReceiverError>;
}
