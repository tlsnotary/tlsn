use crate::ShareConversionError;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use share_conversion_core::gf2_128::Gf2_128ShareConvert;

/// Allows to record the conversion for sender or receiver
pub trait Recorder<T: Gf2_128ShareConvert>: Default {
    fn set_seed(&mut self, seed: [u8; 32]);
    fn record_for_sender(&mut self, input: &[u128]);
    fn record_for_receiver(&mut self, input: &[u128], output: &[u128]);

    /// Allows to check if the tape is valid
    ///
    /// This will replay the whole conversion with the provided inputs/outputs and check if
    /// everything matches
    fn verify(&self) -> Result<(), ShareConversionError>;
}

/// A tape which allows to record inputs and outputs of the conversion.
/// The sender can reveal his tape (thus revealing all his secret inputs) to the receiver
/// who will combine it with her tape to check for any malicious behaviour of the sender.
#[derive(Default)]
pub struct Tape {
    pub(crate) seed: [u8; 32],
    pub(crate) sender_inputs: Vec<u128>,
    pub(crate) receiver_inputs: Vec<u128>,
    pub(crate) receiver_outputs: Vec<u128>,
}

impl<T: Gf2_128ShareConvert> Recorder<T> for Tape {
    fn set_seed(&mut self, seed: [u8; 32]) {
        self.seed = seed;
    }

    fn record_for_sender(&mut self, input: &[u128]) {
        self.sender_inputs.extend_from_slice(input);
    }

    fn record_for_receiver(&mut self, input: &[u128], output: &[u128]) {
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

            let mut ot_output: Vec<u128> = vec![0; 128];
            for (k, number) in ot_output.iter_mut().enumerate() {
                let bit = choices[k] as u128;
                *number = (bit * ot_envelope.one_choices()[k])
                    ^ ((bit ^ 1) * ot_envelope.zero_choices()[k]);
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

impl<T: Gf2_128ShareConvert> Recorder<T> for Void {
    fn set_seed(&mut self, _seed: [u8; 32]) {}

    fn record_for_sender(&mut self, _input: &[u128]) {}

    fn record_for_receiver(&mut self, _input: &[u128], _output: &[u128]) {}

    // Will not be callable from outside
    fn verify(&self) -> Result<(), ShareConversionError> {
        unimplemented!()
    }
}
