//! This crate implements the KOS15 Oblivious Transfer extension protocol.

pub mod errors;
pub mod kos15;

pub use crate::Block;
pub use clmul::Clmul;
pub use errors::*;

pub const BASE_COUNT: usize = 128;

// will be used when implementing KOS15 check
#[allow(dead_code)]
const K: usize = 40;

/// Functionality for "standard" (not random) OT extension. Sender's side
pub trait ExtStandardSendCore {
    type State;
    type BaseSenderSetup;
    type BaseSenderPayload;
    type BaseReceiverSetup;
    type ExtSenderPayload;
    type ExtReceiverSetup;

    fn state(&self) -> &Self::State;

    fn base_setup(
        &mut self,
        base_sender_setup: Self::BaseSenderSetup,
    ) -> Result<Self::BaseReceiverSetup, ExtSenderCoreError>;

    fn base_receive(&mut self, payload: Self::BaseSenderPayload) -> Result<(), ExtSenderCoreError>;

    fn extension_setup(
        &mut self,
        receiver_setup: Self::ExtReceiverSetup,
    ) -> Result<(), ExtSenderCoreError>;

    fn send(&mut self, inputs: &[[Block; 2]])
        -> Result<Self::ExtSenderPayload, ExtSenderCoreError>;

    fn is_complete(&self) -> bool;
}

/// Functionality for random OT
pub trait ExtRandomSendCore: ExtStandardSendCore {
    type ExtDerandomize;

    fn rand_send(
        &mut self,
        inputs: &[[Block; 2]],
        derandomize: Self::ExtDerandomize,
    ) -> Result<Self::ExtSenderPayload, ExtSenderCoreError>;
}

/// Functionality for "standard" (not random) OT extension. Receiver's side
pub trait ExtStandardReceiveCore {
    type State;
    type BaseSenderSetup;
    type BaseSenderPayload;
    type BaseReceiverSetup;
    type ExtSenderPayload;
    type ExtReceiverSetup;

    fn state(&self) -> &Self::State;

    // Receiver in OT extension acts as Sender in base OT and sends the first
    // base OT setup message.
    fn base_setup(&mut self) -> Result<Self::BaseSenderSetup, ExtReceiverCoreError>;

    fn base_send(
        &mut self,
        base_receiver_setup: Self::BaseReceiverSetup,
    ) -> Result<Self::BaseSenderPayload, ExtReceiverCoreError>;

    fn extension_setup(
        &mut self,
        choice: &[bool],
    ) -> Result<Self::ExtReceiverSetup, ExtReceiverCoreError>;

    fn receive(
        &mut self,
        payload: Self::ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError>;

    fn is_complete(&self) -> bool;
}

/// Functionality for random OT extension. Receiver's side
pub trait ExtRandomReceiveCore: ExtStandardReceiveCore {
    type ExtDerandomize;

    fn rand_extension_setup(&mut self) -> Result<Self::ExtReceiverSetup, ExtReceiverCoreError>;

    fn rand_receive(
        &mut self,
        payload: Self::ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError>;

    fn derandomize(
        &mut self,
        choice: &[bool],
    ) -> Result<Self::ExtDerandomize, ExtReceiverCoreError>;
}

#[cfg(test)]
pub mod tests {
    use super::{
        errors::{ExtReceiverCoreError, ExtSenderCoreError},
        kos15::{
            BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, ExtDerandomize, Kos15Receiver,
            Kos15Sender, SenderPayload, SenderSetup,
        },
        ExtStandardReceiveCore, ExtStandardSendCore,
    };
    use crate::utils::u8vec_to_boolvec;
    use crate::Block;
    use pretty_assertions::assert_eq;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use rstest::*;

    pub mod fixtures {
        use super::{BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, SenderSetup};
        use crate::ot::base::tests::fixtures::{choice, values};
        use crate::Block;
        use rstest::*;

        pub struct Data {
            pub base_sender_setup: SenderSetup,
            pub base_receiver_setup: BaseReceiverSetupWrapper,
            pub base_sender_payload: BaseSenderPayloadWrapper,
        }

        #[fixture]
        #[once]
        pub fn ot_ext_core_data(choice: &Vec<bool>, values: &Vec<[Block; 2]>) -> Data {
            use crate::ot::extension::{
                kos15::{Kos15Receiver, Kos15Sender},
                ExtStandardReceiveCore, ExtStandardSendCore,
            };

            let mut sender = Kos15Sender::new(values.len());
            let mut receiver = Kos15Receiver::new(choice.len());
            let base_sender_setup = receiver.base_setup().unwrap();
            let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();
            let base_sender_payload = receiver.base_send(base_receiver_setup.clone()).unwrap();

            Data {
                base_sender_setup,
                base_receiver_setup,
                base_sender_payload,
            }
        }
    }

    #[fixture]
    fn receiver() -> Kos15Receiver {
        Kos15Receiver::new(16)
    }

    #[fixture]
    fn sender() -> Kos15Sender {
        Kos15Sender::new(16)
    }

    #[fixture]
    fn pair_base_setup(
        mut sender: Kos15Sender,
        mut receiver: Kos15Receiver,
    ) -> (Kos15Sender, Kos15Receiver) {
        use super::{ExtStandardReceiveCore, ExtStandardSendCore};
        let base_sender_setup = receiver.base_setup().unwrap();
        let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();
        let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
        sender.base_receive(send_seeds).unwrap();
        (sender, receiver)
    }

    #[fixture]
    fn random_pair_base_setup(
        mut sender: Kos15Sender,
        mut receiver: Kos15Receiver,
    ) -> (Kos15Sender, Kos15Receiver) {
        let base_sender_setup = receiver.base_setup().unwrap();
        let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();
        let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
        sender.base_receive(send_seeds).unwrap();
        (sender, receiver)
    }

    #[rstest]
    fn test_ext_ot(pair_base_setup: (Kos15Sender, Kos15Receiver)) {
        use super::{ExtStandardReceiveCore, ExtStandardSendCore};

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
    // Test that the cointoss check fails on wrong data
    fn test_ext_ot_cointoss_failure(mut sender: Kos15Sender, mut receiver: Kos15Receiver) {
        use super::{ExtStandardReceiveCore, ExtStandardSendCore};

        let mut base_sender_setup = receiver.base_setup().unwrap();
        base_sender_setup.cointoss_commit = [77u8; 32];
        let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();
        let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
        let res = sender.base_receive(send_seeds);
        assert_eq!(res, Err(ExtSenderCoreError::CommitmentCheckFailed));
    }

    #[rstest]
    // Test that the KOS15 check fails on wrong data
    fn test_ext_ot_kos_failure(pair_base_setup: (Kos15Sender, Kos15Receiver)) {
        use super::{ExtStandardReceiveCore, ExtStandardSendCore};

        let (mut sender, mut receiver) = pair_base_setup;

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);

        let mut receiver_setup = receiver.extension_setup(&choice).unwrap();
        receiver_setup.x = [33u8; 16];
        let res = sender.extension_setup(receiver_setup);
        assert_eq!(res, Err(ExtSenderCoreError::ConsistencyCheckFailed));
    }

    #[rstest]
    fn test_ext_ot_batch(pair_base_setup: (Kos15Sender, Kos15Receiver)) {
        use super::{ExtStandardReceiveCore, ExtStandardSendCore};

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

        // Trying to send/receive more OTs should return an error
        let res = sender.send(&[[Block::random(&mut rng), Block::random(&mut rng)]]);
        assert_eq!(res, Err(ExtSenderCoreError::InvalidInputLength));
        let p = SenderPayload {
            ciphertexts: vec![[Block::random(&mut rng), Block::random(&mut rng)]],
        };
        let res = receiver.receive(p);
        assert_eq!(res, Err(ExtReceiverCoreError::AlreadyComplete));

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, received);
    }

    #[rstest]
    fn test_ext_random_ot(random_pair_base_setup: (Kos15Sender, Kos15Receiver)) {
        use super::{ExtRandomReceiveCore, ExtRandomSendCore};

        let (mut sender, mut receiver) = random_pair_base_setup;

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.rand_extension_setup().unwrap();
        sender.extension_setup(receiver_setup).unwrap();

        let derandomize = receiver.derandomize(&choice).unwrap();

        let payload = sender.rand_send(&inputs, derandomize).unwrap();
        let receive = receiver.rand_receive(payload).unwrap();

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive);
    }

    #[rstest]
    fn test_ext_random_ot_batch(random_pair_base_setup: (Kos15Sender, Kos15Receiver)) {
        use super::{ExtRandomReceiveCore, ExtRandomSendCore};

        let (mut sender, mut receiver) = random_pair_base_setup;

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.rand_extension_setup().unwrap();
        sender.extension_setup(receiver_setup).unwrap();

        let mut received: Vec<Block> = Vec::new();
        for (input, choice) in inputs.chunks(4).zip(choice.chunks(4)) {
            assert!(!sender.is_complete());
            assert!(!receiver.is_complete());
            let derandomize = receiver.derandomize(&choice).unwrap();
            let payload = sender.rand_send(&input, derandomize).unwrap();
            received.append(&mut receiver.rand_receive(payload).unwrap());
        }
        assert!(sender.is_complete());
        assert!(receiver.is_complete());

        // Trying to send/receive more OTs should return an error
        let d = ExtDerandomize { flip: vec![true] };
        let res = sender.rand_send(&[[Block::random(&mut rng); 2]], d);
        assert_eq!(res, Err(ExtSenderCoreError::InvalidInputLength));
        let p = SenderPayload {
            ciphertexts: vec![[Block::random(&mut rng); 2]],
        };
        let res = receiver.receive(p);
        assert_eq!(res, Err(ExtReceiverCoreError::AlreadyComplete));

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, received);
    }
}
