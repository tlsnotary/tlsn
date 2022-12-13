//! This crate implements types and imple

pub mod dh_ot;
pub mod errors;

pub use errors::*;

pub use dh_ot::{DhOtReceiver, DhOtSender};

/// The state of an OT sender
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SenderState {
    Initialized,
    Setup,
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
    use crate::{msgs::ot as msgs, Block};
    use utils::iter::u8vec_to_boolvec;

    use rand::{thread_rng, RngCore};
    use rstest::*;

    pub mod fixtures {
        use super::*;

        pub struct Data {
            pub sender_setup: msgs::SenderSetup,
            pub receiver_setup: msgs::ReceiverSetup,
            pub sender_payload: msgs::SenderPayload,
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
            let mut rng = thread_rng();

            let mut sender = DhOtSender::default();
            let sender_setup = sender.setup(&mut rng).unwrap();

            let mut receiver = DhOtReceiver::default();
            let receiver_setup = receiver.setup(&mut rng, choice, sender_setup).unwrap();

            let sender_payload = sender.send(values, receiver_setup.clone()).unwrap();
            let receiver_values = receiver.receive(sender_payload.clone()).unwrap();

            Data {
                sender_setup,
                receiver_setup,
                sender_payload,
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

        let mut sender = DhOtSender::default();
        let sender_setup = sender.setup(&mut rng).unwrap();

        let mut receiver = DhOtReceiver::default();
        let receiver_choices = receiver.setup(&mut rng, &choice, sender_setup).unwrap();

        let send = sender.send(&s_inputs, receiver_choices).unwrap();
        let receive = receiver.receive(send).unwrap();
        assert_eq!(expected, receive);
    }
}
