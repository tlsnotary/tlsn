//! This crate implements types and imple

pub mod dh_ot;
pub mod errors;

pub use errors::*;

/// The state of an OT sender
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SenderState {
    Initialized,
    ReadyToSend,
    Complete,
}

/// The state of an OT receiver
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReceiverState {
    Initialized,
    Setup,
    Complete,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::utils::u8vec_to_boolvec;
    use crate::Block;
    use rand::{thread_rng, RngCore};
    use rstest::*;

    // We test the CO15 scheme only
    use dh_ot::*;

    pub mod fixtures {
        use super::*;

        pub struct Data {
            pub sender_setup: SenderSetup,
            pub receiver_choices: ReceiverChoices,
            pub sender_output: SenderPayload,
            pub receiver_values: Vec<Block>,
        }

        #[fixture]
        #[once]
        pub fn choice() -> Vec<bool> {
            let mut choice = vec![0u8; 16];
            thread_rng().fill_bytes(&mut choice);
            u8vec_to_boolvec(&choice)
        }

        #[fixture]
        #[once]
        pub fn values() -> Vec<[Block; 2]> {
            let mut rng = thread_rng();
            (0..128)
                .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
                .collect()
        }

        #[fixture]
        #[once]
        pub fn ot_core_data(choice: &Vec<bool>, values: &Vec<[Block; 2]>) -> Data {
            let mut sender = DhOtSender::new(values.len());
            let sender_setup = sender.setup();

            let mut receiver = DhOtReceiver::new(choice.len());
            let receiver_choices = receiver.setup(choice, sender_setup).unwrap();

            let sender_output = sender.send(values, receiver_choices.clone()).unwrap();
            let receiver_values = receiver.receive(sender_output.clone()).unwrap();

            Data {
                sender_setup,
                receiver_choices,
                sender_output,
                receiver_values,
            }
        }
    }

    #[rstest]
    fn test_ot() {
        let mut rng = thread_rng();
        let s_inputs: Vec<[Block; 2]> = (0..128)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();
        let mut choice = vec![0u8; 16];
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let expected: Vec<Block> = s_inputs
            .iter()
            .zip(choice.iter())
            .map(|(input, choice)| input[*choice as usize])
            .collect();

        let mut sender = DhOtSender::new(s_inputs.len());
        let sender_setup = sender.setup();

        let mut receiver = DhOtReceiver::new(choice.len());
        let receiver_choices = receiver.setup(&choice, sender_setup).unwrap();

        let send = sender.send(&s_inputs, receiver_choices).unwrap();
        let receive = receiver.receive(send).unwrap();
        assert_eq!(expected, receive);
    }
}
