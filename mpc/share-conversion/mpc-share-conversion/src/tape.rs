use crate::TapeVerificationError;

use mpc_share_conversion_core::{fields::Field, Share};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// A tape which allows to record inputs and outputs of the conversion.
/// The sender can reveal his tape (and rng seed for generating shares) to the receiver
/// who will check it against her tape to detect any malicious behaviour of the sender.
pub(crate) struct SenderTape<F> {
    pub(crate) inputs: Vec<Share<F>>,
}

impl<F> Default for SenderTape<F> {
    fn default() -> Self {
        Self { inputs: Vec::new() }
    }
}

impl<F: Field> SenderTape<F> {
    pub(crate) fn record(&mut self, inputs: &[Share<F>]) {
        self.inputs.extend_from_slice(inputs);
    }
}

pub(crate) struct ReceiverTape<F> {
    pub(crate) inputs: Vec<Share<F>>,
    pub(crate) outputs: Vec<Share<F>>,
}

impl<F> Default for ReceiverTape<F> {
    fn default() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }
}

impl<F: Field> ReceiverTape<F> {
    pub(crate) fn record(&mut self, inputs: &[Share<F>], outputs: &[Share<F>]) {
        self.inputs.extend_from_slice(inputs);
        self.outputs.extend_from_slice(outputs);
    }

    pub(crate) fn verify(
        &self,
        seed: [u8; 32],
        sender_inputs: &[Share<F>],
    ) -> Result<(), TapeVerificationError> {
        let mut rng = ChaCha20Rng::from_seed(seed);

        if sender_inputs.len() != self.inputs.len() {
            return Err(TapeVerificationError::IncorrectLength(
                self.inputs.len(),
                sender_inputs.len(),
            ));
        }

        for ((sender_input, receiver_input), receiver_output) in
            sender_inputs.iter().zip(&self.inputs).zip(&self.outputs)
        {
            if sender_input.ty() != receiver_input.ty() {
                return Err(TapeVerificationError::IncorrectShareType);
            }

            // We now replay the conversion internally
            let (_, expected_summands) = sender_input.convert(&mut rng);

            let expected_share = sender_input.ty().other().new_from_summands(
                &receiver_input
                    .binary_encoding()
                    .iter()
                    .zip(expected_summands)
                    .map(
                        |(choice, summand)| {
                            if *choice {
                                summand[1]
                            } else {
                                summand[0]
                            }
                        },
                    )
                    .collect::<Vec<_>>(),
            );

            // Now we check if the outputs match
            if expected_share.to_inner() != receiver_output.to_inner() {
                return Err(TapeVerificationError::IncorrectShareValue);
            }
        }

        Ok(())
    }
}
