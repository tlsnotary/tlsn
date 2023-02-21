//! An implementation of "Dual Execution" mode which provides authenticity but allows a malicious
//! party to learn n bits of the other party's input with 1/2^n probability of it going undetected.
//!
//! Important! Because currently we do not implement a maliciously secure equality check,
//! all private inputs of the [`DualExFollower`] may be leaked if the [`DualExLeader`] is
//! malicious. Such leakage, however, will be detected by the [`DualExFollower`] during the
//! equality check.

mod config;
mod follower;
mod leader;

pub use config::{DualExConfig, DualExConfigBuilder, DualExConfigBuilderError};
pub use follower::{state as follower_state, DualExFollower};
pub use leader::{state as leader_state, DualExLeader};

use crate::garble::{gc_state, GarbledCircuit};

#[derive(Debug, Clone)]
pub struct DESummary {
    generated: GarbledCircuit<gc_state::FullSummary>,
    evaluated: GarbledCircuit<gc_state::EvaluatedSummary>,
}

impl DESummary {
    /// Create a new [`DESummary`] from the generated and evaluated garbled circuits
    /// of the dual execution protocol
    pub fn new(
        generated: GarbledCircuit<gc_state::FullSummary>,
        evaluated: GarbledCircuit<gc_state::EvaluatedSummary>,
    ) -> Self {
        Self {
            generated,
            evaluated,
        }
    }

    /// Get the full garbled circuit summary
    pub fn get_generator_summary(&self) -> &GarbledCircuit<gc_state::FullSummary> {
        &self.generated
    }

    /// Get the evaluated garbled circuit summary
    pub fn get_evaluator_summary(&self) -> &GarbledCircuit<gc_state::EvaluatedSummary> {
        &self.evaluated
    }
}

#[cfg(test)]
mod tests {
    use crate::garble::{
        commitment::Opening,
        label::{ActiveInputSet, FullInputSet},
        Error, LabelsDigest,
    };

    use super::*;
    use mpc_circuits::{WireGroup, ADDER_64};
    use rand::thread_rng;

    fn evaluated_pair() -> (
        DualExLeader<leader_state::Commit>,
        DualExFollower<follower_state::Reveal>,
    ) {
        let mut rng = thread_rng();
        let circ = ADDER_64.clone();

        let leader = DualExLeader::new(circ.clone());
        let follower = DualExFollower::new(circ.clone());

        let leader_input = circ.input(0).unwrap().to_value(0u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(0u64).unwrap();

        let leader_labels = FullInputSet::generate(&mut rng, &circ, None);
        let follower_labels = FullInputSet::generate(&mut rng, &circ, None);

        let (leader_gc, leader) = leader.garble(leader_labels.clone()).unwrap();

        let (follower_gc, follower) = follower.garble(follower_labels.clone()).unwrap();

        let leader = leader
            .evaluate(
                follower_gc,
                ActiveInputSet::new(vec![
                    follower_labels[0].select(leader_input.value()).unwrap(),
                    follower_labels[1].select(follower_input.value()).unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();

        let follower = follower
            .evaluate(
                leader_gc,
                ActiveInputSet::new(vec![
                    leader_labels[0].select(leader_input.value()).unwrap(),
                    leader_labels[1].select(follower_input.value()).unwrap(),
                ])
                .unwrap(),
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
        let follower_gc = follower.verify(leader_reveal).unwrap();

        assert_eq!(leader_gc.decode().unwrap(), follower_gc.decode().unwrap());
    }

    #[test]
    fn test_leader_fail_reveal() {
        let (leader, follower) = evaluated_pair();

        let (leader_commit, _) = leader.commit();

        let (_, follower) = follower.reveal(leader_commit);

        let malicious_leader_opening = Opening::new(&[0u8; 32]);

        let err = follower.verify(malicious_leader_opening).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }

    #[test]
    fn test_leader_fail_commit() {
        let (leader, follower) = evaluated_pair();

        let (_, leader) = leader.commit();

        let malicious_leader_commit = Opening::new(&[0u8; 32]).commit();

        let (follower_reveal, follower) = follower.reveal(malicious_leader_commit);

        let (leader_opening, _) = leader.check(follower_reveal).unwrap().reveal();

        let err = follower.verify(leader_opening).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }

    #[test]
    fn test_follower_fail_reveal() {
        let (leader, _) = evaluated_pair();

        let (_, leader) = leader.commit();

        let malicious_follower_reveal = LabelsDigest::from_bytes([0u8; 32]);

        let err = leader.check(malicious_follower_reveal).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }
}
