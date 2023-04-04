//! This module implements the KOS15 Oblivious Transfer extension protocol.
//! https://eprint.iacr.org/2015/546.pdf

mod matrix;
/// KOS15 Receiver implementation
pub mod receiver;
/// KOS15 Sender implementation
pub mod sender;
mod utils;

/// The security parameter, i.e. the number of base OTs used for the OT extension
pub const BASE_COUNT: usize = 128;

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{extension::kos15::receiver::error::CommittedOTError, msgs};
    use mpc_core::Block;
    use pretty_assertions::assert_eq;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use receiver::{error::ExtReceiverCoreError, state as r_state, Kos15Receiver};
    use rstest::*;
    use sender::{error::ExtSenderCoreError, state as s_state, Kos15Sender};

    #[fixture]
    fn kos_receiver() -> Kos15Receiver {
        Kos15Receiver::default()
    }

    #[fixture]
    fn kos_sender() -> Kos15Sender {
        Kos15Sender::default()
    }

    #[fixture]
    fn pair_base_setup(
        kos_sender: Kos15Sender,
        kos_receiver: Kos15Receiver,
    ) -> (
        Kos15Sender<s_state::BaseReceive>,
        Kos15Receiver<r_state::BaseSend>,
    ) {
        let (receiver, base_sender_setup) = kos_receiver.base_setup().unwrap();
        let (sender, base_receiver_setup) = kos_sender.base_setup(base_sender_setup).unwrap();
        let (receiver, send_seeds) = receiver.base_send(base_receiver_setup).unwrap();
        let sender = sender.base_receive(send_seeds).unwrap();
        (sender, receiver)
    }

    #[fixture]
    fn input_setup() -> (Vec<bool>, Vec<[Block; 2]>) {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let choice_len: usize = rng.gen_range(1..1024);
        let mut choices = vec![false; choice_len];

        rng.fill::<[bool]>(&mut choices);
        let inputs: Vec<[Block; 2]> = (0..choices.len())
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();
        (choices, inputs)
    }

    #[rstest]
    fn test_ext_ot(
        pair_base_setup: (
            Kos15Sender<s_state::BaseReceive>,
            Kos15Receiver<r_state::BaseSend>,
        ),
        input_setup: (Vec<bool>, Vec<[Block; 2]>),
    ) {
        let (sender, receiver) = pair_base_setup;
        let (choices, inputs) = input_setup;

        let (mut receiver, receiver_setup) = receiver.extension_setup(&choices).unwrap();
        let mut sender = sender
            .extension_setup(choices.len(), receiver_setup)
            .unwrap();

        let payload = sender.send(&inputs).unwrap();
        let receive = receiver.receive(payload).unwrap();

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choices)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive);
    }

    #[rstest]
    // Test that the cointoss check fails on wrong data
    fn test_ext_ot_cointoss_failure(kos_sender: Kos15Sender, kos_receiver: Kos15Receiver) {
        let (receiver, mut base_sender_setup) = kos_receiver.base_setup().unwrap();
        base_sender_setup.cointoss_commit = [77u8; 32];
        let (sender, base_receiver_setup) = kos_sender.base_setup(base_sender_setup).unwrap();
        let (_, send_seeds) = receiver.base_send(base_receiver_setup).unwrap();
        let err = sender.base_receive(send_seeds).unwrap_err();
        assert_eq!(err, ExtSenderCoreError::CommitmentCheckFailed);
    }

    #[rstest]
    // Test that the KOS15 check fails on wrong data
    fn test_ext_ot_kos_failure(
        pair_base_setup: (
            Kos15Sender<s_state::BaseReceive>,
            Kos15Receiver<r_state::BaseSend>,
        ),
        input_setup: (Vec<bool>, Vec<[Block; 2]>),
    ) {
        let (sender, receiver) = pair_base_setup;
        let (choices, _) = input_setup;

        let (_, mut receiver_setup) = receiver.extension_setup(&choices).unwrap();
        receiver_setup.x = [33u8; 16];
        let err = sender
            .extension_setup(choices.len(), receiver_setup)
            .unwrap_err();
        assert_eq!(err, ExtSenderCoreError::ConsistencyCheckFailed);
    }

    #[rstest]
    fn test_ext_ot_batch(
        pair_base_setup: (
            Kos15Sender<s_state::BaseReceive>,
            Kos15Receiver<r_state::BaseSend>,
        ),
        input_setup: (Vec<bool>, Vec<[Block; 2]>),
    ) {
        let (sender, receiver) = pair_base_setup;
        let (choices, inputs) = input_setup;

        let (mut receiver, receiver_setup) = receiver.extension_setup(&choices).unwrap();
        let mut sender = sender
            .extension_setup(choices.len(), receiver_setup)
            .unwrap();

        // Try sending too much. This should fail
        let oversized_inputs = &[inputs.as_slice(), inputs.as_slice()].concat();
        assert_eq!(
            sender.send(&oversized_inputs),
            Err(ExtSenderCoreError::InvalidInputLength)
        );

        let mut received: Vec<Block> = Vec::new();
        for chunk in inputs.chunks(4) {
            assert!(!sender.is_complete());
            assert!(!receiver.is_complete());
            let payload = sender.send(&chunk).unwrap();
            received.append(&mut receiver.receive(payload).unwrap());
        }
        assert!(sender.is_complete());
        assert!(receiver.is_complete());

        // Trying to send more OTs should return an error
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let sender = sender
            .send(&[[Block::random(&mut rng), Block::random(&mut rng)]])
            .expect_err("Sending more OTs should be a state error");
        assert_eq!(sender, ExtSenderCoreError::InvalidInputLength);

        let oversized_payload = msgs::ExtSenderPayload {
            ciphertexts: vec![[Block::random(&mut rng), Block::random(&mut rng)]],
        };

        // Trying to receive more OTs should return an error
        let receiver = receiver
            .receive(oversized_payload)
            .expect_err("Sending more OTs should be a state error");
        assert_eq!(receiver, ExtReceiverCoreError::InvalidPayloadSize);

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choices)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, received);
    }

    #[rstest]
    fn test_ext_random_ot(
        pair_base_setup: (
            Kos15Sender<s_state::BaseReceive>,
            Kos15Receiver<r_state::BaseSend>,
        ),
        input_setup: (Vec<bool>, Vec<[Block; 2]>),
    ) {
        let (sender, receiver) = pair_base_setup;
        let (choices, inputs) = input_setup;

        let (mut receiver, receiver_setup) = receiver.rand_extension_setup(choices.len()).unwrap();
        let mut sender = sender
            .rand_extension_setup(choices.len(), receiver_setup)
            .unwrap();

        let derandomize = receiver.derandomize(&choices).unwrap();

        let payload = sender.rand_send(&inputs, derandomize).unwrap();
        let receive = receiver.receive(payload).unwrap();

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choices)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive);
    }

    #[rstest]
    fn test_ext_random_ot_batch(
        pair_base_setup: (
            Kos15Sender<s_state::BaseReceive>,
            Kos15Receiver<r_state::BaseSend>,
        ),
        input_setup: (Vec<bool>, Vec<[Block; 2]>),
    ) {
        let (sender, receiver) = pair_base_setup;
        let (choices, inputs) = input_setup;

        let (mut receiver, receiver_setup) = receiver.rand_extension_setup(choices.len()).unwrap();
        let mut sender = sender
            .rand_extension_setup(choices.len(), receiver_setup)
            .unwrap();

        let mut received: Vec<Block> = Vec::new();
        for (input, choice) in inputs.chunks(4).zip(choices.chunks(4)) {
            assert!(!sender.is_complete());
            assert!(!receiver.is_complete());
            let derandomize = receiver.derandomize(&choice).unwrap();
            let payload = sender.rand_send(&input, derandomize).unwrap();
            received.append(&mut receiver.receive(payload).unwrap());
        }
        assert!(sender.is_complete());
        assert!(receiver.is_complete());

        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Trying to send more OTs should return an error
        let add_derand = msgs::ExtDerandomize { flip: vec![true] };
        let sender = sender
            .rand_send(&[[Block::random(&mut rng); 2]], add_derand)
            .expect_err("Sending more OTs should be a state error");
        assert_eq!(sender, ExtSenderCoreError::InvalidInputLength);

        // Trying to receive more OTs should return an error
        let add_ciphers = msgs::ExtSenderPayload {
            ciphertexts: vec![[Block::random(&mut rng); 2]],
        };
        let receiver = receiver
            .receive(add_ciphers)
            .expect_err("Sending more OTs should be state error");
        assert_eq!(receiver, ExtReceiverCoreError::CiphertextCountWrong);

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choices)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, received);
    }

    // Test the wrong padding
    #[rstest]
    fn test_wrong_padding(
        pair_base_setup: (
            Kos15Sender<s_state::BaseReceive>,
            Kos15Receiver<r_state::BaseSend>,
        ),
        input_setup: (Vec<bool>, Vec<[Block; 2]>),
    ) {
        // create one instances with "bad" column counts
        let (sender, receiver) = pair_base_setup;
        let (choices, _) = input_setup;
        let (_, mut receiver_setup) = receiver.extension_setup(&choices).unwrap();

        // sender must not accept more or less columns
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let coinflip: bool = rng.gen();

        if coinflip {
            receiver_setup.table.extend(vec![0u8; BASE_COUNT]);
        } else {
            receiver_setup.table.drain(0..BASE_COUNT * 2);
        }

        let sender = sender
            .extension_setup(choices.len(), receiver_setup)
            .expect_err("invalid padding should be an error");
        assert_eq!(sender, ExtSenderCoreError::InvalidPadding);
    }

    #[rstest]
    fn test_committed_ot(input_setup: (Vec<bool>, Vec<[Block; 2]>)) {
        let (choices, inputs) = input_setup;
        let (sender, mut receiver) = (Kos15Sender::default(), Kos15Receiver::default());

        let commitment = sender.commit_to_seed();
        receiver.store_commitment(commitment.0);

        let (receiver, message) = receiver.base_setup().unwrap();
        let (sender, message) = sender.base_setup(message).unwrap();

        let (receiver, message) = receiver.base_send(message).unwrap();
        let sender = sender.base_receive(message).unwrap();

        let (mut receiver, receiver_setup) = receiver.rand_extension_setup(choices.len()).unwrap();
        let mut sender = sender
            .rand_extension_setup(choices.len(), receiver_setup)
            .unwrap();

        let message = receiver.derandomize(&choices).unwrap();

        let sender_output = sender.rand_send(&inputs, message).unwrap();
        let _ = receiver.receive(sender_output).unwrap();

        let reveal = unsafe { sender.reveal().unwrap() };

        let check = receiver.verify(reveal, &inputs);
        assert!(check.is_ok());
    }

    #[rstest]
    fn test_committed_ot_fail(input_setup: (Vec<bool>, Vec<[Block; 2]>)) {
        let (choices, mut inputs) = input_setup;
        let (sender, mut receiver) = (Kos15Sender::default(), Kos15Receiver::default());

        let commitment = sender.commit_to_seed();
        receiver.store_commitment(commitment.0);

        let (receiver, message) = receiver.base_setup().unwrap();
        let (sender, message) = sender.base_setup(message).unwrap();

        let (receiver, message) = receiver.base_send(message).unwrap();
        let sender = sender.base_receive(message).unwrap();

        let (mut receiver, receiver_setup) = receiver.rand_extension_setup(choices.len()).unwrap();
        let mut sender = sender
            .rand_extension_setup(choices.len(), receiver_setup)
            .unwrap();

        let message = receiver.derandomize(&choices).unwrap();

        let sender_output = sender.rand_send(&inputs, message).unwrap();
        let _ = receiver.receive(sender_output).unwrap();

        let reveal = unsafe { sender.reveal().unwrap() };
        *inputs.last_mut().unwrap() = *inputs.first().unwrap();

        let check = receiver.verify(reveal, &inputs);
        assert!(check.unwrap_err() == CommittedOTError::Verify);
    }

    #[rstest]
    fn test_ot_count_disagree(input_setup: (Vec<bool>, Vec<[Block; 2]>)) {
        let (choices, _) = input_setup;
        let (sender, mut receiver) = (Kos15Sender::default(), Kos15Receiver::default());

        let commitment = sender.commit_to_seed();
        receiver.store_commitment(commitment.0);

        let (receiver, message) = receiver.base_setup().unwrap();
        let (sender, message) = sender.base_setup(message).unwrap();

        let (receiver, message) = receiver.base_send(message).unwrap();
        let sender = sender.base_receive(message).unwrap();

        let (_receiver, receiver_setup) = receiver.rand_extension_setup(choices.len()).unwrap();
        let sender = sender.rand_extension_setup(choices.len() + 1, receiver_setup);
        assert_eq!(sender.unwrap_err(), ExtSenderCoreError::OTNumberDisagree);
    }
}
