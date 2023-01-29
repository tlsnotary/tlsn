use crate::ShareConversionError;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use share_conversion_core::{fields::Field, ShareConvert};

/// Allows to record the conversion for sender or receiver
pub trait Recorder<T: ShareConvert<Inner = U>, U: Field>: Default {
    fn set_seed(&mut self, seed: [u8; 32]);
    fn record_for_sender(&mut self, input: &[U]);
    fn record_for_receiver(&mut self, input: &[U], output: &[U]);

    /// Allows to check if the tape is valid
    ///
    /// This will replay the whole conversion with the provided inputs/outputs and check if
    /// everything matches
    fn verify(&self) -> Result<(), ShareConversionError>;
}

/// A tape which allows to record inputs and outputs of the conversion.
/// The sender can reveal his tape (thus revealing all his secret inputs) to the receiver
/// who will combine it with her tape to check for any malicious behaviour of the sender.
pub struct Tape<T: Field> {
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

impl<T: ShareConvert<Inner = U>, U: Field> Recorder<T, U> for Tape<U> {
    fn set_seed(&mut self, seed: [u8; 32]) {
        self.seed = seed;
    }

    fn record_for_sender(&mut self, input: &[U]) {
        self.sender_inputs.extend_from_slice(input);
    }

    fn record_for_receiver(&mut self, input: &[U], output: &[U]) {
        self.receiver_inputs.extend_from_slice(input);
        self.receiver_outputs.extend_from_slice(output);
    }

    fn verify(&self) -> Result<(), ShareConversionError> {
        let mut rng = ChaCha12Rng::from_seed(self.seed);

        for ((sender_input, receiver_input), receiver_output) in self
            .sender_inputs
            .iter()
            .zip(&self.receiver_inputs)
            .zip(&self.receiver_outputs)
        {
            // We now replay the conversion internally
            let (_, ot_envelope) = T::new(*sender_input).convert(&mut rng)?;
            let choices = T::new(*receiver_input).choices();

            let mut ot_output: Vec<U> = vec![U::zero(); U::BIT_SIZE as usize];
            for (k, number) in ot_output.iter_mut().enumerate() {
                *number = if choices[k] {
                    ot_envelope.one_choices()[k]
                } else {
                    ot_envelope.zero_choices()[k]
                };
            }

            // Now we check if the outputs match
            let expected = T::Output::from_sender_values(&ot_output);
            if expected.inner() != *receiver_output {
                return Err(ShareConversionError::VerifyTapeFailed);
            }
        }
        Ok(())
    }
}

/// A zero-sized type not doing anything
///
/// We can use this to instantiate a conversion algorithm which does not provide recording
/// functionality.
#[derive(Default)]
pub struct Void;

impl<T: ShareConvert<Inner = U>, U: Field> Recorder<T, U> for Void {
    fn set_seed(&mut self, _seed: [u8; 32]) {}

    fn record_for_sender(&mut self, _input: &[U]) {}

    fn record_for_receiver(&mut self, _input: &[U], _output: &[U]) {}

    // Will not be callable from outside
    fn verify(&self) -> Result<(), ShareConversionError> {
        unimplemented!()
    }
}
