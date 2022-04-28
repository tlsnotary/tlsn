pub mod errors;
pub mod receiver;
pub mod sender;

pub use crate::ot::base::{
    ReceiverSetup as BaseReceiverSetup, SenderPayload as BaseSenderPayload,
    SenderSetup as BaseSenderSetup,
};
pub use crate::Block;
pub use errors::*;
pub use receiver::{ExtDerandomize, ExtReceiverCore, ExtReceiverSetup};
pub use sender::{ExtSenderCore, ExtSenderPayload};

pub const BASE_COUNT: usize = 128;

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

    fn is_complete(&self) -> bool;
}

pub trait ExtRandomSendCore: ExtSendCore {
    fn state(&self) -> sender::State {
        ExtSendCore::state(self)
    }

    fn base_setup(
        &mut self,
        base_sender_setup: BaseSenderSetup,
    ) -> Result<BaseReceiverSetup, ExtSenderCoreError> {
        ExtSendCore::base_setup(self, base_sender_setup)
    }

    fn base_receive(&mut self, payload: BaseSenderPayload) -> Result<(), ExtSenderCoreError> {
        ExtSendCore::base_receive(self, payload)
    }

    fn extension_setup(
        &mut self,
        receiver_setup: ExtReceiverSetup,
    ) -> Result<(), ExtSenderCoreError> {
        ExtSendCore::extension_setup(self, receiver_setup)
    }

    fn send(
        &mut self,
        inputs: &[[Block; 2]],
        derandomize: ExtDerandomize,
    ) -> Result<ExtSenderPayload, ExtSenderCoreError>;

    fn is_complete(&self) -> bool {
        ExtSendCore::is_complete(self)
    }
}

pub trait ExtReceiveCore {
    fn state(&self) -> &receiver::State;

    fn base_setup(&mut self) -> Result<BaseSenderSetup, ExtReceiverCoreError>;

    fn base_send(
        &mut self,
        base_receiver_setup: BaseReceiverSetup,
    ) -> Result<BaseSenderPayload, ExtReceiverCoreError>;

    fn extension_setup(
        &mut self,
        choice: &[bool],
    ) -> Result<ExtReceiverSetup, ExtReceiverCoreError>;

    fn receive(&mut self, payload: ExtSenderPayload) -> Result<Vec<Block>, ExtReceiverCoreError>;

    fn is_complete(&self) -> bool;
}

pub trait ExtRandomReceiveCore: ExtReceiveCore {
    fn state(&self) -> &receiver::State {
        ExtReceiveCore::state(self)
    }

    fn base_setup(&mut self) -> Result<BaseSenderSetup, ExtReceiverCoreError> {
        ExtReceiveCore::base_setup(self)
    }

    fn base_send(
        &mut self,
        base_receiver_setup: BaseReceiverSetup,
    ) -> Result<BaseSenderPayload, ExtReceiverCoreError> {
        ExtReceiveCore::base_send(self, base_receiver_setup)
    }

    fn extension_setup(&mut self) -> Result<ExtReceiverSetup, ExtReceiverCoreError>;

    fn derandomize(&mut self, choice: &[bool]) -> Result<ExtDerandomize, ExtReceiverCoreError>;

    fn receive(&mut self, payload: ExtSenderPayload) -> Result<Vec<Block>, ExtReceiverCoreError>;

    fn is_complete(&self) -> bool {
        ExtReceiveCore::is_complete(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{ExtReceiverCore, ExtSenderCore};
    use crate::utils::u8vec_to_boolvec;
    use crate::Block;
    use pretty_assertions::assert_eq;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use rstest::*;

    #[fixture]
    fn receiver() -> ExtReceiverCore {
        ExtReceiverCore::new(16)
    }

    #[fixture]
    fn sender() -> ExtSenderCore {
        ExtSenderCore::new(16)
    }

    #[fixture]
    fn pair_base_setup(
        mut sender: ExtSenderCore,
        mut receiver: ExtReceiverCore,
    ) -> (ExtSenderCore, ExtReceiverCore) {
        use super::{ExtReceiveCore, ExtSendCore};
        let base_sender_setup = receiver.base_setup().unwrap();
        let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();
        let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
        sender.base_receive(send_seeds).unwrap();
        (sender, receiver)
    }

    #[fixture]
    fn random_pair_base_setup(
        mut sender: ExtSenderCore,
        mut receiver: ExtReceiverCore,
    ) -> (ExtSenderCore, ExtReceiverCore) {
        use super::{ExtRandomReceiveCore, ExtRandomSendCore};
        let base_sender_setup = receiver.base_setup().unwrap();
        let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();
        let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
        sender.base_receive(send_seeds).unwrap();
        (sender, receiver)
    }

    #[rstest]
    fn test_ext_ot(pair_base_setup: (ExtSenderCore, ExtReceiverCore)) {
        use super::{ExtReceiveCore, ExtSendCore};

        let (mut sender, mut receiver) = pair_base_setup;

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.extension_setup(&choice).unwrap();
        sender.extension_setup(receiver_setup).unwrap();

        let payload = sender.send(&inputs).unwrap();
        let receive = receiver.receive(payload).unwrap();

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive);
    }

    #[rstest]
    fn test_ext_ot_batch(pair_base_setup: (ExtSenderCore, ExtReceiverCore)) {
        use super::{ExtReceiveCore, ExtSendCore};

        let (mut sender, mut receiver) = pair_base_setup;

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.extension_setup(&choice).unwrap();
        sender.extension_setup(receiver_setup).unwrap();

        let mut received: Vec<Block> = Vec::new();
        for chunk in inputs.chunks(4) {
            assert!(!sender.is_complete());
            assert!(!receiver.is_complete());
            let payload = sender.send(&chunk).unwrap();
            received.append(&mut receiver.receive(payload).unwrap());
        }
        assert!(sender.is_complete());
        assert!(receiver.is_complete());

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, received);
    }

    #[rstest]
    fn test_ext_random_ot(random_pair_base_setup: (ExtSenderCore, ExtReceiverCore)) {
        use super::{ExtRandomReceiveCore, ExtRandomSendCore};

        let (mut sender, mut receiver) = random_pair_base_setup;

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.extension_setup().unwrap();
        sender.extension_setup(receiver_setup).unwrap();

        let derandomize = receiver.derandomize(&choice).unwrap();

        let payload = sender.send(&inputs, derandomize).unwrap();
        let receive = receiver.receive(payload).unwrap();

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive);
    }

    #[rstest]
    fn test_ext_random_ot_batch(random_pair_base_setup: (ExtSenderCore, ExtReceiverCore)) {
        use super::{ExtRandomReceiveCore, ExtRandomSendCore};

        let (mut sender, mut receiver) = random_pair_base_setup;

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.extension_setup().unwrap();
        sender.extension_setup(receiver_setup).unwrap();

        let mut received: Vec<Block> = Vec::new();
        for (input, choice) in inputs.chunks(4).zip(choice.chunks(4)) {
            assert!(!sender.is_complete());
            assert!(!receiver.is_complete());
            let derandomize = receiver.derandomize(&choice).unwrap();
            let payload = sender.send(&input, derandomize).unwrap();
            received.append(&mut receiver.receive(payload).unwrap());
        }
        assert!(sender.is_complete());
        assert!(receiver.is_complete());

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, received);
    }
}
