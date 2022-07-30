use crate::{
    garble::{
        circuit::{BinaryLabel, EvaluatedGarbledCircuit, InputValue},
        decode, evaluate_garbled_circuit, generate_garbled_circuit, Error, FullGarbledCircuit,
        GarbledCircuit,
    },
    utils::{choose, sha256},
    Block,
};
use mpc_circuits::Circuit;

use aes::{Aes128, NewBlockCipher};
use std::{marker::PhantomData, sync::Arc};

#[derive(Clone, PartialEq)]
pub struct OutputCheck([u8; 32]);

#[derive(Clone, PartialEq)]
pub struct OutputCommit([u8; 32]);

impl OutputCheck {
    pub fn new(expected: &[u8]) -> Self {
        Self(sha256(expected))
    }
}

impl OutputCommit {
    pub fn new(check: &OutputCheck) -> Self {
        Self(sha256(&check.0))
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Generator {}
    impl Sealed for super::Evaluator {}
    impl Sealed for super::Commit {}
    impl Sealed for super::Reveal {}
    impl Sealed for super::Check {}
    impl Sealed for super::Complete {}
    impl Sealed for super::Leader {}
    impl Sealed for super::Follower {}
}
pub trait Role: sealed::Sealed {}
pub trait State: sealed::Sealed {}

pub struct Leader;
pub struct Follower;

impl Role for Leader {}
impl Role for Follower {}

pub struct Generator {
    circ: Arc<Circuit>,
}

pub struct Evaluator {
    circ: Arc<Circuit>,
    gc: FullGarbledCircuit,
}

pub struct Commit {
    circ: Arc<Circuit>,
    output_labels: Vec<BinaryLabel>,
    output: Vec<bool>,
    check: OutputCheck,
}

pub struct Reveal {
    circ: Arc<Circuit>,
    output_labels: Vec<BinaryLabel>,
    output: Vec<bool>,
    check: OutputCheck,
}

pub struct Check {
    circ: Arc<Circuit>,
    output_labels: Vec<BinaryLabel>,
    output: Vec<bool>,
    check: OutputCheck,
    commit: Option<OutputCommit>,
}

pub struct Complete {
    circ: Arc<Circuit>,
    output_labels: Vec<BinaryLabel>,
    output: Vec<bool>,
}

impl State for Generator {}
impl State for Evaluator {}
impl State for Commit {}
impl State for Reveal {}
impl State for Check {}
impl State for Complete {}

/// An implementation of "Dual Execution" mode which provides authenticity
/// but may leak all private inputs of the `Follower` if the `Leader` is malicious. Either party,
/// if malicious, can learn bits of the others input with 1/2^n probability of it going undetected.
pub struct DualExecution<R, S = Generator>
where
    R: Role,
    S: State,
{
    state: S,
    _role: PhantomData<R>,
}

impl DualExecution<Leader> {
    pub fn new_leader(circ: Arc<Circuit>) -> DualExecution<Leader, Generator> {
        DualExecution {
            state: Generator { circ },
            _role: PhantomData::<Leader>,
        }
    }
}

impl DualExecution<Follower> {
    pub fn new_follower(circ: Arc<Circuit>) -> DualExecution<Follower, Generator> {
        DualExecution {
            state: Generator { circ },
            _role: PhantomData::<Follower>,
        }
    }
}

impl<R> DualExecution<R, Generator>
where
    R: Role,
{
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        inputs: &[InputValue],
        input_labels: &[[BinaryLabel; 2]],
        public_labels: &[BinaryLabel; 2],
        delta: &Block,
    ) -> Result<(GarbledCircuit, DualExecution<R, Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let gc = generate_garbled_circuit(
            &cipher,
            self.state.circ.clone(),
            delta,
            input_labels,
            public_labels,
        )?;

        Ok((
            gc.to_evaluator(inputs, true),
            DualExecution {
                state: Evaluator {
                    gc,
                    circ: self.state.circ,
                },
                _role: self._role,
            },
        ))
    }
}

impl DualExecution<Leader, Evaluator> {
    /// Evaluate `Follower` circuit
    pub fn evaluate(
        self,
        gc: &GarbledCircuit,
        input_labels: &[BinaryLabel],
    ) -> Result<DualExecution<Leader, Commit>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let output_labels = evaluate_garbled_circuit(&cipher, &gc, input_labels)?;

        let output = decode(
            &output_labels,
            gc.decoding.as_ref().ok_or(Error::PeerError(
                "Peer did not provide label decoding".to_string(),
            ))?,
        );

        let expected_labels = choose(self.state.gc.output_labels(), &output);

        let check = OutputCheck::new(
            &expected_labels
                .iter()
                .chain(output_labels.iter())
                .map(|label| label.value().to_be_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        );

        Ok(DualExecution {
            state: Commit {
                circ: self.state.circ,
                output_labels,
                output,
                check,
            },
            _role: self._role,
        })
    }
}

impl DualExecution<Follower, Evaluator> {
    /// Evaluate `Leader` circuit
    pub fn evaluate(
        self,
        gc: &GarbledCircuit,
        input_labels: &[BinaryLabel],
    ) -> Result<DualExecution<Follower, Reveal>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let output_labels = evaluate_garbled_circuit(&cipher, &gc, input_labels)?;

        let output = decode(
            &output_labels,
            gc.decoding.as_ref().ok_or(Error::PeerError(
                "Peer did not provide label decoding".to_string(),
            ))?,
        );

        let expected_labels = choose(self.state.gc.output_labels(), &output);

        let check = OutputCheck::new(
            &output_labels
                .iter()
                .chain(expected_labels.iter())
                .map(|label| label.value().to_be_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        );

        Ok(DualExecution {
            state: Reveal {
                circ: self.state.circ,
                output_labels,
                output,
                check,
            },
            _role: self._role,
        })
    }
}

impl DualExecution<Leader, Commit> {
    /// Commit to output
    pub fn commit(self) -> (OutputCommit, DualExecution<Leader, Check>) {
        (
            OutputCommit::new(&self.state.check),
            DualExecution {
                state: Check {
                    circ: self.state.circ,
                    output_labels: self.state.output_labels,
                    output: self.state.output,
                    check: self.state.check,
                    commit: None,
                },
                _role: self._role,
            },
        )
    }
}

impl DualExecution<Follower, Reveal> {
    /// Receive commitment from `Leader` and reveal `Follower` check
    pub fn reveal(self, commit: OutputCommit) -> (OutputCheck, DualExecution<Follower, Check>) {
        (
            self.state.check.clone(),
            DualExecution {
                state: Check {
                    circ: self.state.circ,
                    output_labels: self.state.output_labels,
                    output: self.state.output,
                    check: self.state.check,
                    commit: Some(commit),
                },
                _role: self._role,
            },
        )
    }
}

impl DualExecution<Leader, Check> {
    /// Check `Follower` output matches expected
    pub fn check(self, check: OutputCheck) -> Result<DualExecution<Leader, Reveal>, Error> {
        // If this fails then the peer was cheating and your private inputs were potentially leaked
        // with a probability of 1/2^n per bit, and you should call the police immediately
        if check != self.state.check {
            return Err(Error::PeerError(
                "Peer sent invalid output check".to_string(),
            ));
        }

        Ok(DualExecution {
            state: Reveal {
                circ: self.state.circ,
                output_labels: self.state.output_labels,
                output: self.state.output,
                check: self.state.check,
            },
            _role: self._role,
        })
    }
}

impl DualExecution<Leader, Reveal> {
    /// Open output commitment to `Follower`
    pub fn reveal(self) -> (OutputCheck, DualExecution<Leader, Complete>) {
        (
            self.state.check,
            DualExecution {
                state: Complete {
                    circ: self.state.circ,
                    output_labels: self.state.output_labels,
                    output: self.state.output,
                },
                _role: self._role,
            },
        )
    }
}

impl DualExecution<Follower, Check> {
    /// Check `Leader` output matches expected
    pub fn check(self, check: OutputCheck) -> Result<DualExecution<Follower, Complete>, Error> {
        // If this fails then the peer was cheating and your private inputs were potentially leaked
        // and you should call the police immediately
        if check != self.state.check {
            return Err(Error::PeerError(
                "Peer sent invalid output check".to_string(),
            ));
        }

        // If this fails then the peer was definitely cheating
        if OutputCommit::new(&check) != self.state.commit.unwrap() {
            return Err(Error::PeerError(
                "Peer sent output check which does not match previous commitment".to_string(),
            ));
        }

        Ok(DualExecution {
            state: Complete {
                circ: self.state.circ,
                output_labels: self.state.output_labels,
                output: self.state.output,
            },
            _role: self._role,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::garble::{circuit::choose_labels, generate_labels, generate_public_labels};

    use super::*;
    use mpc_circuits::ADDER_64;
    use rand::thread_rng;
    use std::sync::Arc;

    #[test]
    fn test_success() {
        let mut rng = thread_rng();
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());

        let alice = DualExecution::new_leader(circ.clone());
        let bob = DualExecution::new_follower(circ.clone());

        // Alice and Bob have u64 inputs of 1
        let value = [vec![false; 63], vec![true; 1]].concat();
        let alice_inputs = [InputValue::new(circ.input(0).clone(), &value)];
        let bob_inputs = [InputValue::new(circ.input(1).clone(), &value)];

        let (alice_labels, alice_delta) = generate_labels(&mut rng, None, 128, 0);
        let alice_pub_labels = generate_public_labels(&mut rng, &alice_delta);

        let (bob_labels, bob_delta) = generate_labels(&mut rng, None, 128, 0);
        let bob_pub_labels = generate_public_labels(&mut rng, &bob_delta);

        let (alice_gc, alice) = alice
            .garble(
                &alice_inputs,
                &alice_labels,
                &alice_pub_labels,
                &alice_delta,
            )
            .unwrap();

        let (bob_gc, bob) = bob
            .garble(&bob_inputs, &bob_labels, &bob_pub_labels, &bob_delta)
            .unwrap();

        let (alice_commit, alice) = alice
            .evaluate(
                &bob_gc,
                &choose_labels(
                    &bob_labels,
                    alice_inputs[0].wires(),
                    alice_inputs[0].value(),
                ),
            )
            .unwrap()
            .commit();

        let (bob_reveal, bob) = bob
            .evaluate(
                &alice_gc,
                &choose_labels(&alice_labels, bob_inputs[0].wires(), bob_inputs[0].value()),
            )
            .unwrap()
            .reveal(alice_commit);

        let (alice_reveal, _) = alice.check(bob_reveal).unwrap().reveal();
        let _ = bob.check(alice_reveal).unwrap();
    }
}
