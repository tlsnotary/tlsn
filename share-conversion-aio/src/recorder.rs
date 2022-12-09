use rand::{Rng, SeedableRng};

pub trait Recorder<T: SeedableRng + Rng, U>: Default + Send {
    fn record_sender_input(&mut self, seed: <T as SeedableRng>::Seed, input: &[U]);
    fn set_sender_inputs(&mut self, seeds: Vec<<T as SeedableRng>::Seed>, inputs: Vec<Vec<U>>);
    fn record_receiver_input(&mut self, input: &[U]);
    fn record_receiver_output(&mut self, output: &[U]);
    fn verify(&self, converter: impl FnMut(&mut T, &U) -> U) -> bool;
}

#[derive(Debug)]
pub struct Tape<T, U> {
    seeds: Vec<T>,
    sender_inputs: Vec<Vec<U>>,
    receiver_inputs: Vec<Vec<U>>,
    receiver_outputs: Vec<Vec<U>>,
}

impl<T, U> Default for Tape<T, U> {
    fn default() -> Self {
        Tape {
            seeds: vec![],
            sender_inputs: vec![],
            receiver_inputs: vec![],
            receiver_outputs: vec![],
        }
    }
}

impl<T: SeedableRng + Rng + Send, U: Default + PartialEq + Send + Clone> Recorder<T, U>
    for Tape<<T as SeedableRng>::Seed, U>
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

    fn verify(&self, mut converter: impl FnMut(&mut T, &U) -> U) -> bool {
        //TODO: This is probably not yet correct
        for ((seed, input), output) in std::iter::zip(self.seeds.iter(), self.sender_inputs.iter())
            .zip(self.receiver_inputs.iter())
        {
            let mut rng = T::from_seed(*seed);
            for (a, b) in input.iter().zip(output.iter()) {
                if converter(&mut rng, a) != *b {
                    return false;
                }
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

    fn verify(&self, _converter: impl FnMut(&mut T, &U) -> U) -> bool {
        unimplemented!()
    }
}
