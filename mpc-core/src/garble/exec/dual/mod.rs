//! An implementation of "Dual Execution" mode which provides authenticity but allows a malicious
//! party to learn n bits of the other party's input with 1/2^n probability of it going undetected.
//!
//! Important! Because currently we do not implement a maliciously secure equality check,
//! all private inputs of the [`DualExFollower`] may be leaked if the [`DualExLeader`] is
//! malicious. Such leakage, however, will be detected by the [`DualExFollower`] during the
//! equality check.

mod follower;
mod leader;

pub use follower::{state as follower_state, DualExFollower};
pub use leader::{state as leader_state, DualExLeader};

#[cfg(test)]
mod tests {
    use crate::garble::{commitment::Opening, Error, InputLabels, OutputCheck};

    use super::*;
    use mpc_circuits::{Circuit, WireGroup, ADDER_64};
    use rand::thread_rng;
    use std::sync::Arc;

    fn evaluated_pair() -> (
        DualExLeader<leader_state::Commit>,
        DualExFollower<follower_state::Reveal>,
    ) {
        let mut rng = thread_rng();
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());

        let leader = DualExLeader::new(circ.clone());
        let follower = DualExFollower::new(circ.clone());

        let leader_input = circ.input(0).unwrap().to_value(0u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(0u64).unwrap();

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
                follower_gc,
                &[follower_labels[0].select(&leader_input).unwrap()],
            )
            .unwrap();

        let follower = follower
            .evaluate(
                leader_gc,
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
        let follower_gc = follower.verify(leader_reveal).unwrap();

        assert_eq!(leader_gc.decode().unwrap(), follower_gc.decode().unwrap());
    }

    #[test]
    fn test_leader_fail_reveal() {
        let (leader, follower) = evaluated_pair();

        let (leader_commit, _) = leader.commit();

        let (_, follower) = follower.reveal(leader_commit);

        let malicious_leader_opening = Opening::new(&OutputCheck::new((&[], &[])).0);

        let err = follower.verify(malicious_leader_opening).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }

    #[test]
    fn test_leader_fail_commit() {
        let (leader, follower) = evaluated_pair();

        let (_, leader) = leader.commit();

        let malicious_leader_commit = Opening::new(&OutputCheck::new((&[], &[])).0).commit();

        let (follower_reveal, follower) = follower.reveal(malicious_leader_commit);

        let (leader_opening, _) = leader.check(follower_reveal).unwrap().reveal();

        let err = follower.verify(leader_opening).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }

    #[test]
    fn test_follower_fail_reveal() {
        let (leader, _) = evaluated_pair();

        let (_, leader) = leader.commit();

        let malicious_follower_reveal = OutputCheck::new((&[], &[]));

        let err = leader.check(malicious_follower_reveal).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }
}
