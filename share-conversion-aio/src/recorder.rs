use rand::{CryptoRng, Rng, SeedableRng};
use share_conversion_core::gf2_128::Gf2_128ShareConvert;

pub trait Recorder<T: SeedableRng + Rng, U>: Default + Send {
    fn record_sender_input(&mut self, seed: <T as SeedableRng>::Seed, input: &[U]);
    fn set_sender_inputs(&mut self, seeds: Vec<<T as SeedableRng>::Seed>, inputs: Vec<Vec<U>>);
    fn record_receiver_input(&mut self, input: &[U]);
    fn record_receiver_output(&mut self, output: &[U]);
    fn verify(&self) -> bool;
}

pub trait Verify {
    fn verify<R: Rng + CryptoRng>(&self, other: &Self, expected: &Self, rng: &mut R) -> bool;
}

impl<T: Gf2_128ShareConvert<Output = T>> Verify for T {
    fn verify<R: Rng + CryptoRng>(&self, other: &Self, expected: &Self, rng: &mut R) -> bool {
        let (_, ot_envelope) = self.convert(rng);
        let choices = other.choices();

        let mut ot_output: Vec<u128> = vec![0; 128];
        for (k, number) in ot_output.iter_mut().enumerate() {
            let bit = choices[k] as u128;
            *number = (bit * ot_envelope.1[k]) ^ ((bit ^ 1) * ot_envelope.0[k]);
        }
        let converted = Self::from_choice(&ot_output);
        converted == *expected
    }
}

pub struct Tape<T: SeedableRng + Rng, U> {
    pub(crate) seeds: Vec<<T as SeedableRng>::Seed>,
    pub(crate) sender_inputs: Vec<Vec<U>>,
    pub(crate) receiver_inputs: Vec<Vec<U>>,
    pub(crate) receiver_outputs: Vec<Vec<U>>,
}

impl<T: SeedableRng + Rng, U> Default for Tape<T, U> {
    fn default() -> Self {
        Tape {
            seeds: vec![],
            sender_inputs: vec![],
            receiver_inputs: vec![],
            receiver_outputs: vec![],
        }
    }
}

impl<T: SeedableRng + Rng + Send, U: PartialEq + Send + Clone> Recorder<T, U> for Tape<T, U>
where
    <T as SeedableRng>::Seed: Send + Copy,
{
    fn record_sender_input(&mut self, seed: <T as SeedableRng>::Seed, input: &[U]) {
        self.seeds.push(seed);
        self.sender_inputs.push(input.to_vec());
    }
    fn set_sender_inputs(&mut self, seeds: Vec<<T as SeedableRng>::Seed>, inputs: Vec<Vec<U>>) {
        self.seeds = seeds;
        self.sender_inputs = inputs;
    }

    fn record_receiver_input(&mut self, input: &[U]) {
        self.receiver_inputs.push(input.to_vec());
    }

    fn record_receiver_output(&mut self, output: &[U]) {
        self.receiver_outputs.push(output.to_vec());
    }

    fn verify(&self) -> bool {
        //TODO: This is probably not yet correct
        for ((seed, sender_input), (receiver_input, receiver_output)) in
            std::iter::zip(self.seeds.iter(), self.sender_inputs.iter()).zip(std::iter::zip(
                self.receiver_inputs.iter(),
                self.receiver_outputs.iter(),
            ))
        {
            let mut rng = T::from_seed(*seed);
            for (a, (b, c)) in sender_input.iter().zip(std::iter::zip(
                receiver_input.iter(),
                receiver_output.iter(),
            )) {
                return false;
            }
        }
        true
    }
}

#[derive(Default)]
pub struct Void;

impl<T: SeedableRng + Rng, U> Recorder<T, U> for Void {
    fn record_sender_input(&mut self, _seed: <T as SeedableRng>::Seed, _input: &[U]) {}

    fn set_sender_inputs(&mut self, _seeds: Vec<<T as SeedableRng>::Seed>, _inputs: Vec<Vec<U>>) {}

    fn record_receiver_input(&mut self, _input: &[U]) {}

    fn record_receiver_output(&mut self, _output: &[U]) {}

    fn verify(&self) -> bool {
        unimplemented!()
    }
}
