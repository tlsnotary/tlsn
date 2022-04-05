pub mod errors;
pub mod receiver;
pub mod sender;

pub use crate::ot::base::{
    ReceiverSetup as BaseReceiverSetup, SenderPayload as BaseSenderPayload,
    SenderSetup as BaseSenderSetup,
};
pub use crate::Block;
pub use errors::*;
pub use receiver::{ExtReceiverCore, ExtReceiverSetup};
pub use sender::{ExtSenderCore, ExtSenderPayload};

// will be used when implementing KOS15 check
#[allow(dead_code)]
const K: usize = 40;

pub trait ExtSendCore {
    fn state(&self) -> sender::State;

    fn base_setup(
        &mut self,
        base_sender_setup: BaseSenderSetup,
    ) -> Result<BaseReceiverSetup, ExtSenderCoreError>;

    fn base_receive(&mut self, payload: BaseSenderPayload) -> Result<(), ExtSenderCoreError>;

    fn extension_setup(
        &mut self,
        receiver_setup: ExtReceiverSetup,
    ) -> Result<(), ExtSenderCoreError>;

    fn send(&mut self, inputs: &[[Block; 2]]) -> Result<ExtSenderPayload, ExtSenderCoreError>;
}

pub trait ExtReceiveCore {
    fn state(&self) -> receiver::State;

    fn base_setup(&mut self) -> Result<BaseSenderSetup, ExtReceiverCoreError>;

    fn base_send(
        &mut self,
        base_receiver_setup: BaseReceiverSetup,
    ) -> Result<BaseSenderPayload, ExtReceiverCoreError>;

    fn extension_setup(
        &mut self,
        choice: &[bool],
    ) -> Result<ExtReceiverSetup, ExtReceiverCoreError>;

    fn receive(
        &mut self,
        choice: &[bool],
        payload: ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::u8vec_to_boolvec;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use rstest::*;

    #[rstest]
    fn test_ext_ot() {
        let mut receiver = ExtReceiverCore::default();
        let base_sender_setup = receiver.base_setup().unwrap();

        let mut sender = ExtSenderCore::default();
        let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();

        let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
        sender.base_receive(send_seeds).unwrap();

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|i| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.extension_setup(&choice).unwrap();
        sender.extension_setup(receiver_setup).unwrap();

        let send = sender.send(&inputs).unwrap();
        let receive = receiver.receive(&choice, send).unwrap();

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive);
    }
}
