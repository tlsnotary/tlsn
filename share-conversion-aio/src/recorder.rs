use rand::{Rng, SeedableRng};

pub trait Recorder<T: SeedableRng + Rng, U>: Default + Send {
    fn record_input(&mut self, seed: <T as SeedableRng>::Seed, input: Vec<U>);
    fn set_inputs(&mut self, seeds: Vec<<T as SeedableRng>::Seed>, inputs: Vec<Vec<U>>);
    fn record_output(&mut self, output: Vec<U>);
    fn verify(&self, converter: impl FnMut(&mut T, &U) -> U) -> bool;
}

#[derive(Debug)]
pub struct Tape<T, U> {
    seeds: Vec<T>,
    inputs: Vec<Vec<U>>,
    outputs: Vec<Vec<U>>,
}

impl<T, U> Default for Tape<T, U> {
    fn default() -> Self {
        Tape {
            seeds: vec![],
            inputs: vec![],
            outputs: vec![],
        }
    }
}

impl<T: SeedableRng + Rng + Send, U: Default + PartialEq + Send> Recorder<T, U>
    for Tape<<T as SeedableRng>::Seed, U>
where
    <T as SeedableRng>::Seed: Send + Copy,
{
    fn record_input(&mut self, seed: <T as SeedableRng>::Seed, input: Vec<U>) {
        self.seeds.push(seed);
        self.inputs.push(input);
    }
    fn set_inputs(&mut self, seeds: Vec<<T as SeedableRng>::Seed>, inputs: Vec<Vec<U>>) {
        self.seeds = seeds;
        self.inputs = inputs;
    }

    fn record_output(&mut self, output: Vec<U>) {
        self.outputs.push(output);
    }

    fn verify(&self, mut converter: impl FnMut(&mut T, &U) -> U) -> bool {
        for ((seed, input), output) in
            std::iter::zip(self.seeds.iter(), self.inputs.iter()).zip(self.outputs.iter())
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
    fn record_input(&mut self, _seed: <T as SeedableRng>::Seed, _input: Vec<U>) {}

    fn set_inputs(&mut self, _seeds: Vec<<T as SeedableRng>::Seed>, _inputs: Vec<Vec<U>>) {}

    fn record_output(&mut self, _output: Vec<U>) {}

    fn verify(&self, _converter: impl FnMut(&mut T, &U) -> U) -> bool {
        false
    }
}
