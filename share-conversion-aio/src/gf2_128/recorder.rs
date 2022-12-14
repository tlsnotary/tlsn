use rand_chacha::ChaCha12Rng;
use share_conversion_core::gf2_128::Gf2_128ShareConvert;

pub trait Recorder<T: Gf2_128ShareConvert> {
    fn set_seed(&mut self, seed: [u8; 32]);
    fn record_for_sender(&mut self, input: &[u128]);
    fn record_for_receiver(&mut self, input: &[u128], output: &[u128]);
    fn verify(&self) -> bool;
}

pub struct Tape {
    pub(crate) seed: [u8; 32],
    pub(crate) sender_inputs: Vec<u128>,
    pub(crate) receiver_inputs: Vec<u128>,
    pub(crate) receiver_outputs: Vec<u128>,
}

impl Default for Tape {
    fn default() -> Self {
        Tape {
            seed: [0; 32],
            sender_inputs: vec![],
            receiver_inputs: vec![],
            receiver_outputs: vec![],
        }
    }
}

impl<T: Gf2_128ShareConvert> Recorder<T> for Tape {
    fn set_seed(&mut self, seed: [u8; 32]) {
        self.seed = seed;
    }

    fn record_for_sender(&mut self, input: &[u128]) {
        self.sender_inputs.extend_from_slice(input);
    }

    fn record_for_receiver(&mut self, input: &[u128], output: &[u128]) {
        self.reciver_inputs.extend_from_slice(input);
        self.reciver_outputs.extend_from_slice(output);
    }

    fn verify(&self) -> bool {
        let mut rng = ChaCha12Rng::from_seed(self.seed);
        for (sender_input, (receiver_input, receiver_output)) in self.sender_inputs.iter().zip(
            std::iter::zip(self.receiver_inputs.iter(), self.receiver_outputs.iter()),
        ) {
            let (_, ot_envelope) = T::new(sender_input);
            let choices = receiver_input.choices();

            let mut ot_output: Vec<u128> = vec![0; 128];
            for (k, number) in ot_output.iter_mut().enumerate() {
                let bit = choices[k] as u128;
                *number = (bit * ot_envelope.1[k]) ^ ((bit ^ 1) * ot_envelope.0[k]);
            }
            let expected = T::Output::from_choice(&ot_output);
            if expected != receiver_output {
                return false;
            }
        }
        true
    }
}

#[derive(Default)]
pub struct Void;

impl<T: Gf2_128ShareConvert> Recorder<T> for Void {
    fn set_seed(&mut self, seed: [u8; 32]) {}

    fn record_for_sender(&mut self, input: &[u128]) {}

    fn record_for_receiver(&mut self, input: &[u128], output: &[u128]) {}

    fn verify(&self) -> bool {
        unimplemented!()
    }
}
