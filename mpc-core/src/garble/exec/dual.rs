//! An implementation of "Dual Execution" mode which provides authenticity
//! but may leak all private inputs of the [`DualExFollower`] if the [`DualExLeader`] is malicious. Either party,
//! if malicious, can learn bits of the others input with 1/2^n probability of it going undetected.
use crate::{
    garble::{
        circuit::EvaluatedGarbledCircuit, label::OutputLabels, Delta, Error, FullGarbledCircuit,
        GarbledCircuit, InputLabels, WireLabel, WireLabelPair,
    },
    utils::sha256,
};
use mpc_circuits::{Circuit, InputValue};

use aes::{Aes128, NewBlockCipher};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OutputCheck([u8; 32]);

#[derive(Clone, PartialEq)]
pub struct OutputCommit([u8; 32]);

impl OutputCheck {
    /// Creates new output check
    ///
    /// This output check is a hash of the output wire labels from the peer's circuit along with the
    /// expected labels from the callers garbled circuit. The expected labels are determined using
    /// the decoded output values from evaluating the peer's garbled circuit.
    pub fn new(labels: (&[OutputLabels<WireLabel>], &[OutputLabels<WireLabel>])) -> Self {
        let bytes: Vec<u8> = labels
            .0
            .iter()
            .chain(labels.1.iter())
            .map(|labels| labels.to_be_bytes())
            .flatten()
            .collect();
        Self(sha256(&bytes))
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
}

pub trait State: sealed::Sealed {}

pub struct Generator {
    circ: Arc<Circuit>,
}

pub struct Evaluator {
    circ: Arc<Circuit>,
    gc: FullGarbledCircuit,
}

pub struct Commit {
    circ: Arc<Circuit>,
    evaluated_gc: EvaluatedGarbledCircuit,
    check: OutputCheck,
}

pub struct Reveal {
    circ: Arc<Circuit>,
    evaluated_gc: EvaluatedGarbledCircuit,
    check: OutputCheck,
}

pub struct Check {
    circ: Arc<Circuit>,
    evaluated_gc: EvaluatedGarbledCircuit,
    check: OutputCheck,
    commit: Option<OutputCommit>,
}

impl State for Generator {}
impl State for Evaluator {}
impl State for Commit {}
impl State for Reveal {}
impl State for Check {}

pub struct DualExLeader<S = Generator>
where
    S: State,
{
    state: S,
}

pub struct DualExFollower<S = Generator>
where
    S: State,
{
    state: S,
}

impl DualExLeader {
    pub fn new(circ: Arc<Circuit>) -> DualExLeader<Generator> {
        DualExLeader {
            state: Generator { circ },
        }
    }
}

impl DualExFollower {
    pub fn new(circ: Arc<Circuit>) -> DualExFollower<Generator> {
        DualExFollower {
            state: Generator { circ },
        }
    }
}

impl DualExLeader<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<(GarbledCircuit, DualExLeader<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let gc =
            FullGarbledCircuit::generate(&cipher, self.state.circ.clone(), delta, input_labels)?;

        Ok((
            gc.to_evaluator(inputs, true),
            DualExLeader {
                state: Evaluator {
                    gc,
                    circ: self.state.circ,
                },
            },
        ))
    }
}

impl DualExFollower<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<(GarbledCircuit, DualExFollower<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let gc =
            FullGarbledCircuit::generate(&cipher, self.state.circ.clone(), delta, input_labels)?;

        Ok((
            gc.to_evaluator(inputs, true),
            DualExFollower {
                state: Evaluator {
                    gc,
                    circ: self.state.circ,
                },
            },
        ))
    }
}

impl DualExLeader<Evaluator> {
    /// Evaluate [`DualExFollower`] circuit
    pub fn evaluate(
        self,
        gc: &GarbledCircuit,
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<DualExLeader<Commit>, Error> {
        if !gc.has_encoding() {
            return Err(Error::PeerError(
                "Peer did not provide label encoding".to_string(),
            ));
        }

        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let evaluated_gc = gc.evaluate(&cipher, input_labels)?;

        let output = evaluated_gc.decode()?;

        let mut expected_labels: Vec<OutputLabels<WireLabel>> =
            Vec::with_capacity(self.state.circ.output_count());
        // Here we use the output values from the peer's circuit to select the corresponding output labels from our garbled circuit
        for (labels, value) in self.state.gc.output_labels().iter().zip(output.iter()) {
            expected_labels.push(labels.select(value)?);
        }

        let check = OutputCheck::new((&expected_labels, &evaluated_gc.output_labels()));

        Ok(DualExLeader {
            state: Commit {
                circ: self.state.circ,
                evaluated_gc,
                check,
            },
        })
    }
}

impl DualExFollower<Evaluator> {
    /// Evaluate [`DualExLeader`] circuit
    pub fn evaluate(
        self,
        gc: &GarbledCircuit,
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<DualExFollower<Reveal>, Error> {
        if !gc.has_encoding() {
            return Err(Error::PeerError(
                "Peer did not provide label encoding".to_string(),
            ));
        }

        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();

        let evaluated_gc = gc.evaluate(&cipher, input_labels)?;

        let output = evaluated_gc.decode()?;

        let mut expected_labels: Vec<OutputLabels<WireLabel>> =
            Vec::with_capacity(self.state.circ.output_count());
        // Here we use the output values from the peer's circuit to select the corresponding output labels from our garbled circuit
        for (labels, value) in self.state.gc.output_labels().iter().zip(output.iter()) {
            expected_labels.push(labels.select(value)?);
        }

        let check = OutputCheck::new((&evaluated_gc.output_labels(), &expected_labels));

        Ok(DualExFollower {
            state: Reveal {
                circ: self.state.circ,
                evaluated_gc,
                check,
            },
        })
    }
}

impl DualExLeader<Commit> {
    /// Commit to output
    pub fn commit(self) -> (OutputCommit, DualExLeader<Check>) {
        (
            OutputCommit::new(&self.state.check),
            DualExLeader {
                state: Check {
                    circ: self.state.circ,
                    evaluated_gc: self.state.evaluated_gc,
                    check: self.state.check,
                    commit: None,
                },
            },
        )
    }
}

impl DualExFollower<Reveal> {
    /// Receive commitment from [`DualExLeader`] and reveal [`DualExFollower`] check
    pub fn reveal(self, commit: OutputCommit) -> (OutputCheck, DualExFollower<Check>) {
        (
            self.state.check.clone(),
            DualExFollower {
                state: Check {
                    circ: self.state.circ,
                    evaluated_gc: self.state.evaluated_gc,
                    check: self.state.check,
                    commit: Some(commit),
                },
            },
        )
    }
}

impl DualExLeader<Check> {
    /// Check [`DualExFollower`] output matches expected
    pub fn check(self, check: OutputCheck) -> Result<DualExLeader<Reveal>, Error> {
        // If this fails then the peer was cheating and your private inputs were potentially leaked
        // with a probability of 1/2^n per bit, and you should call the police immediately
        if check != self.state.check {
            return Err(Error::PeerError(
                "Peer sent invalid output check".to_string(),
            ));
        }

        Ok(DualExLeader {
            state: Reveal {
                circ: self.state.circ,
                evaluated_gc: self.state.evaluated_gc,
                check: self.state.check,
            },
        })
    }
}

impl DualExLeader<Reveal> {
    /// Open output commitment to [`DualExFollower`]
    pub fn reveal(self) -> (OutputCheck, EvaluatedGarbledCircuit) {
        (self.state.check, self.state.evaluated_gc)
    }
}

impl DualExFollower<Check> {
    /// Check [`DualExLeader`] output matches expected
    pub fn check(self, check: OutputCheck) -> Result<EvaluatedGarbledCircuit, Error> {
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

        Ok(self.state.evaluated_gc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_circuits::ADDER_64;
    use rand::thread_rng;
    use std::sync::Arc;

    fn evaluated_pair() -> (DualExLeader<Commit>, DualExFollower<Reveal>) {
        let mut rng = thread_rng();
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());

        let leader = DualExLeader::new(circ.clone());
        let follower = DualExFollower::new(circ.clone());

        // Leader and Follower have u64 inputs of 1
        let value = [vec![false; 63], vec![true; 1]].concat();
        let leader_input = circ.input(0).unwrap().to_value(&value).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(&value).unwrap();

        let (leader_labels, leader_delta) = InputLabels::generate(&mut rng, &circ, None);
        let (follower_labels, follower_delta) = InputLabels::generate(&mut rng, &circ, None);

        let (leader_gc, leader) = leader
            .garble(&[leader_input.clone()], &leader_labels, leader_delta)
            .unwrap();

        let (follower_gc, follower) = follower
            .garble(&[follower_input.clone()], &follower_labels, follower_delta)
            .unwrap();

        let leader = leader
            .evaluate(
                &follower_gc,
                &[follower_labels[0].select(&leader_input).unwrap()],
            )
            .unwrap();

        let follower = follower
            .evaluate(
                &leader_gc,
                &[leader_labels[1].select(&follower_input).unwrap()],
            )
            .unwrap();

        (leader, follower)
    }

    #[test]
    fn test_success() {
        let (leader, follower) = evaluated_pair();

        let (leader_commit, leader) = leader.commit();
        let (follower_reveal, follower) = follower.reveal(leader_commit);

        let (leader_reveal, leader_gc) = leader.check(follower_reveal).unwrap().reveal();
        let follower_gc = follower.check(leader_reveal).unwrap();

        assert_eq!(leader_gc.decode().unwrap(), follower_gc.decode().unwrap());
    }

    #[test]
    fn test_leader_fail_reveal() {
        let (leader, follower) = evaluated_pair();

        let (leader_commit, _) = leader.commit();
        let (_, follower) = follower.reveal(leader_commit);

        let malicious_leader_reveal = OutputCheck::new((&[], &[]));

        let follower_result = follower.check(malicious_leader_reveal);

        assert!(matches!(follower_result, Err(Error::PeerError(_))));
    }

    #[test]
    fn test_leader_fail_commit() {
        let (leader, follower) = evaluated_pair();

        let (_, leader) = leader.commit();

        let malicious_leader_commit = OutputCommit::new(&OutputCheck::new((&[], &[])));

        let (follower_reveal, follower) = follower.reveal(malicious_leader_commit);

        let (leader_reveal, _) = leader.check(follower_reveal).unwrap().reveal();

        let follower_result = follower.check(leader_reveal);

        assert!(matches!(follower_result, Err(Error::PeerError(_))));
    }

    #[test]
    fn test_follower_fail_reveal() {
        let (leader, _) = evaluated_pair();

        let (_, leader) = leader.commit();

        let malicious_follower_reveal = OutputCheck::new((&[], &[]));

        let leader_result = leader.check(malicious_follower_reveal);

        assert!(matches!(leader_result, Err(Error::PeerError(_))));
    }
}
