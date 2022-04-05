pub mod errors;
pub mod receiver;
pub mod sender;

pub use errors::*;

pub use receiver::{ReceiverCore, ReceiverSetup};
pub use sender::{SenderCore, SenderPayload, SenderSetup};

pub trait SendCore {
    fn state(&self) -> sender::State;

    fn setup(&mut self) -> SenderSetup;

    fn send(
        &mut self,
        inputs: &[[crate::Block; 2]],
        receiver_setup: ReceiverSetup,
    ) -> Result<SenderPayload, SenderCoreError>;
}

pub trait ReceiveCore {
    fn state(&self) -> receiver::State;

    fn setup(
        &mut self,
        choice: &[bool],
        sender_setup: SenderSetup,
    ) -> Result<ReceiverSetup, ReceiverCoreError>;

    fn receive(
        &mut self,
        choice: &[bool],
        payload: SenderPayload,
    ) -> Result<Vec<crate::Block>, ReceiverCoreError>;
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::utils::u8vec_to_boolvec;
    use crate::Block;
    use rand::{thread_rng, RngCore};
    use rstest::*;

    pub mod fixtures {
        use super::*;

        pub struct Data {
            pub sender_setup: SenderSetup,
            pub receiver_setup: ReceiverSetup,
            pub sender_payload: SenderPayload,
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
                .map(|i| [Block::random(&mut rng), Block::random(&mut rng)])
                .collect()
        }

        #[fixture]
        #[once]
        pub fn ot_core_data(choice: &Vec<bool>, values: &Vec<[Block; 2]>) -> Data {
            let mut sender = SenderCore::default();
            let sender_setup = sender.setup();

            let mut receiver = ReceiverCore::default();
            let receiver_setup = receiver.setup(choice, sender_setup.clone()).unwrap();

            let sender_payload = sender.send(values, receiver_setup.clone()).unwrap();
            let receiver_values = receiver.receive(choice, sender_payload.clone()).unwrap();

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
            .map(|i| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();
        let mut choice = vec![0u8; 16];
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let expected: Vec<Block> = s_inputs
            .iter()
            .zip(choice.iter())
            .map(|(input, choice)| input[*choice as usize])
            .collect();

        let mut sender = SenderCore::default();
        let sender_setup = sender.setup();

        let mut receiver = ReceiverCore::default();
        let receiver_setup = receiver.setup(&choice, sender_setup).unwrap();

        let send = sender.send(&s_inputs, receiver_setup).unwrap();
        let receive = receiver.receive(&choice, send).unwrap();
        assert_eq!(expected, receive);
    }
}
