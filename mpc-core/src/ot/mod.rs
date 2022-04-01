pub mod base;
pub mod errors;
pub mod extension;

pub use base::*;
pub use errors::*;
pub use extension::*;

use crate::Block;

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

pub type ChaChaAesOtSender = OtSenderCore<ChaCha12Rng, Aes128>;
pub type ChaChaAesOtReceiver = OtReceiverCore<ChaCha12Rng, Aes128>;

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

#[derive(Debug, Clone)]
pub enum OtMessage {
    BaseSenderSetup(BaseOtSenderSetup),
    BaseSenderPayload(BaseOtSenderPayload),
    BaseReceiverSetup(BaseOtReceiverSetup),
    ReceiverSetup(OtReceiverSetup),
    SenderPayload(OtSenderPayload),
}

pub trait OtSend {
    fn state(&self) -> OtSenderState;

    fn base_setup(
        &mut self,
        base_sender_setup: BaseOtSenderSetup,
    ) -> Result<BaseOtReceiverSetup, OtSenderCoreError>;

    fn base_receive(&mut self, payload: BaseOtSenderPayload) -> Result<(), OtSenderCoreError>;

    fn extension_setup(&mut self, receiver_setup: OtReceiverSetup)
        -> Result<(), OtSenderCoreError>;

    fn send(&mut self, inputs: &[[Block; 2]]) -> Result<OtSenderPayload, OtSenderCoreError>;
}

pub trait OtReceive {
    fn state(&self) -> OtReceiverState;

    fn base_setup(&mut self) -> Result<BaseOtSenderSetup, OtReceiverCoreError>;

    fn base_send(
        &mut self,
        base_receiver_setup: BaseOtReceiverSetup,
    ) -> Result<BaseOtSenderPayload, OtReceiverCoreError>;

    fn extension_setup(&mut self, choice: &[bool]) -> Result<OtReceiverSetup, OtReceiverCoreError>;

    fn receive(
        &mut self,
        choice: &[bool],
        payload: OtSenderPayload,
    ) -> Result<Vec<Block>, OtReceiverCoreError>;
}
