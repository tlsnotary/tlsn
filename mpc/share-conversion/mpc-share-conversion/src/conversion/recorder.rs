use crate::ShareConversionError;
use mpc_share_conversion_core::{fields::Field, ShareConvert};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

/// A tape which allows to record inputs and outputs of the conversion.
/// The sender can reveal his tape (thus revealing all his secret inputs) to the receiver
/// who will combine it with her tape to check for any malicious behaviour of the sender.
pub(crate) struct Tape<T: Field> {
    pub(crate) seed: [u8; 32],
    pub(crate) sender_inputs: Vec<T>,
    pub(crate) receiver_inputs: Vec<T>,
    pub(crate) receiver_outputs: Vec<T>,
}

impl<T: Field> Default for Tape<T> {
    fn default() -> Self {
        let seed = [0_u8; 32];
        let sender_inputs = vec![];
        let receiver_inputs = vec![];
        let receiver_outputs = vec![];
        Self {
            seed,
            sender_inputs,
            receiver_inputs,
            receiver_outputs,
        }
    }
}

impl<T: Field> Tape<T> {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            ..Default::default()
        }
    }

    pub(crate) fn set_seed(&mut self, seed: [u8; 32]) {
        self.seed = seed;
    }

    pub(crate) fn record_for_sender(&mut self, input: &[T]) {
        self.sender_inputs.extend_from_slice(input);
    }

    pub(crate) fn record_for_receiver(&mut self, input: &[T], output: &[T]) {
        self.receiver_inputs.extend_from_slice(input);
        self.receiver_outputs.extend_from_slice(output);
    }

    pub(crate) fn verify<S: ShareConvert<Inner = T>>(&self) -> Result<(), ShareConversionError> {
        let mut rng = ChaCha12Rng::from_seed(self.seed);

        for ((sender_input, receiver_input), receiver_output) in self
            .sender_inputs
            .iter()
            .zip(&self.receiver_inputs)
            .zip(&self.receiver_outputs)
        {
            // We now replay the conversion internally
            let (_, ot_envelope) = S::new(*sender_input).convert(&mut rng)?;
            let choices = S::new(*receiver_input).choices();

            let mut ot_output: Vec<T> = vec![T::zero(); T::BIT_SIZE as usize];
            for (k, number) in ot_output.iter_mut().enumerate() {
                *number = if choices[k] {
                    ot_envelope.one_choices()[k]
                } else {
                    ot_envelope.zero_choices()[k]
                };
            }

            // Now we check if the outputs match
            let expected = S::Output::from_sender_values(&ot_output);
            if expected.inner() != *receiver_output {
                return Err(ShareConversionError::VerifyTapeFailed);
            }
        }

        Ok(())
    }
}
