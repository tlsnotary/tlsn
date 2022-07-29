use crate::{
    garble::{
        circuit::BinaryLabel, decode, evaluate_garbled_circuit, generate_garbled_circuit, Error,
        FullGarbledCircuit, GarbledCircuit,
    },
    utils::{choose, sha256},
    Block,
};
use mpc_circuits::Circuit;

use aes::{Aes128, NewBlockCipher};
use std::sync::Arc;

#[derive(PartialEq)]
pub struct OutputCheck([u8; 32]);
pub struct OutputCommit([u8; 32]);

impl OutputCheck {
    pub fn new(expected: &[u8]) -> Self {
        Self(sha256(expected))
    }

    fn inner(&self) -> &[u8] {
        &self.0
    }
}

impl OutputCommit {
    pub fn new(check: &OutputCheck) -> Self {
        Self(sha256(check.inner()))
    }
}

pub trait State {}
impl State for Generator {}
impl State for Evaluator {}
impl State for Check {}

pub struct Generator {}

pub struct Evaluator {
    gc: FullGarbledCircuit,
}

pub struct Check {
    gc: FullGarbledCircuit,
    ev_output_labels: Vec<BinaryLabel>,
    ev_output: Vec<bool>,
    check: OutputCheck,
    commit: Option<OutputCommit>,
}

pub struct DualExecution<S = Generator>
where
    S: State,
{
    state: S,
    circ: Arc<Circuit>,
    role: bool,
}

impl DualExecution {
    pub fn new(circ: Arc<Circuit>, role: bool) -> DualExecution<Generator> {
        Self {
            state: Generator {},
            circ,
            role,
        }
    }
}

impl DualExecution<Generator> {
    pub fn garble(
        self,
        input_labels: &[[BinaryLabel; 2]],
        public_labels: &[BinaryLabel; 2],
        delta: &Block,
    ) -> Result<DualExecution<Evaluator>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let gc = generate_garbled_circuit(
            &cipher,
            self.circ.clone(),
            delta,
            input_labels,
            public_labels,
        )?;

        Ok(DualExecution {
            state: Evaluator { gc },
            circ: self.circ,
            role: self.role,
        })
    }
}

impl DualExecution<Evaluator> {
    pub fn garbled_circuit(&self) -> &FullGarbledCircuit {
        &self.state.gc
    }

    pub fn evaluate(
        self,
        gc: &GarbledCircuit,
        input_labels: &[BinaryLabel],
    ) -> Result<DualExecution<Check>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let output_labels = evaluate_garbled_circuit(&cipher, &gc, input_labels)?;

        let output = decode(
            &output_labels,
            gc.decoding.as_ref().ok_or(Error::PeerError(
                "Peer did not provide label decoding".to_string(),
            ))?,
        );

        let our_labels = choose(self.state.gc.output_labels(), &output);

        let check = if self.role {
            OutputCheck::new(
                &our_labels
                    .iter()
                    .chain(output_labels.iter())
                    .map(|label| label.value().to_be_bytes())
                    .flatten()
                    .collect::<Vec<u8>>(),
            )
        } else {
            OutputCheck::new(
                &output_labels
                    .iter()
                    .chain(our_labels.iter())
                    .map(|label| label.value().to_be_bytes())
                    .flatten()
                    .collect::<Vec<u8>>(),
            )
        };

        let commit = self.role.then(|| OutputCommit::new(&check));

        Ok(DualExecution {
            state: Check {
                gc: self.state.gc,
                ev_output_labels: output_labels,
                ev_output: output,
                check,
                commit,
            },
            circ: self.circ,
            role: self.role,
        })
    }
}

impl DualExecution<Check> {
    pub fn commit(&self) -> Option<&OutputCommit> {
        self.state.commit.as_ref()
    }

    pub fn check(&self) -> &OutputCheck {
        &self.state.check
    }
}

#[cfg(test)]
mod tests {
    use crate::garble::{generate_labels, generate_public_labels};

    use super::*;
    use mpc_circuits::ADDER_64;
    use rand::thread_rng;
    use std::sync::Arc;

    #[test]
    fn test_success() {
        let mut rng = thread_rng();
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());

        let alice = DualExecution::new(circ.clone(), true);
        let bob = DualExecution::new(circ.clone(), false);

        // Alice and Bob have u64 inputs of 1
        let alice_input = [vec![false; 63], vec![true; 1]].concat();
        let bob_input = [vec![false; 63], vec![true; 1]].concat();

        let (alice_labels, alice_delta) = generate_labels(&mut rng, None, 128, 0);
        let alice_pub_labels = generate_public_labels(&mut rng, &alice_delta);
        let alice_inputs = choose(&alice_labels[..64], &alice_input);

        let (bob_labels, bob_delta) = generate_labels(&mut rng, None, 128, 0);
        let bob_pub_labels = generate_public_labels(&mut rng, &bob_delta);
        let bob_inputs = choose(&bob_labels[64..], &bob_input);

        let alice = alice
            .garble(&alice_labels, &alice_pub_labels, &alice_delta)
            .unwrap();
        let alice_gc = alice.garbled_circuit().to_evaluator(&alice_inputs, true);

        let bob = bob
            .garble(&bob_labels, &bob_pub_labels, &bob_delta)
            .unwrap();
        let bob_gc = bob.garbled_circuit().to_evaluator(&bob_inputs, true);

        let alice = alice
            .evaluate(&bob_gc, &choose(&bob_labels[..64], &alice_input))
            .unwrap();
        let bob = bob
            .evaluate(&alice_gc, &choose(&alice_labels[64..], &bob_input))
            .unwrap();

        assert!(alice.check() == bob.check());
    }
}
