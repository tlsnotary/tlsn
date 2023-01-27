mod config;
mod follower;
mod leader;

pub use config::{DEAPConfig, DEAPConfigBuilder, DEAPConfigBuilderError};
pub use follower::{state as follower_state, DEAPFollower};
pub use leader::{state as leader_state, DEAPLeader};

#[cfg(test)]
mod tests {
    use crate::garble::{commitment::Opening, ActiveInputSet, Delta, Error, FullInputSet};
    use std::sync::Arc;

    use super::*;
    use mpc_circuits::{Circuit, OutputValue, WireGroup, ADDER_64};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    fn evaluated_pair(
        circ: Arc<Circuit>,
    ) -> (
        Vec<OutputValue>,
        DEAPLeader<leader_state::Commit>,
        DEAPFollower<follower_state::Reveal>,
    ) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let leader = DEAPLeader::new(circ.clone());
        let follower = DEAPFollower::new(circ.clone());

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

        let (purported_output, follower) = follower
            .evaluate(
                leader_gc,
                ActiveInputSet::new(vec![
                    leader_labels[0].select(leader_input.value()).unwrap(),
                    leader_labels[1].select(follower_input.value()).unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();

        (purported_output, leader, follower)
    }

    #[test]
    fn test_success() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (purported_output, leader, follower) = evaluated_pair(circ.clone());

        let (leader_commit, leader) = leader.commit();
        let (follower_output, follower) = follower.reveal(leader_commit);

        let (leader_output_values, leader) = leader.decode(follower_output.into()).unwrap();

        let (follower_opening, follower) = follower.open();

        let leader = leader.validate(follower_opening.into()).unwrap();
        let leader_opening = leader.reveal();

        follower.verify(leader_opening).unwrap();

        assert_eq!(leader_output_values, purported_output)
    }

    #[test]
    fn test_leader_fail_reveal() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (_, leader, follower) = evaluated_pair(circ.clone());

        let (leader_commit, leader) = leader.commit();
        let (follower_output, follower) = follower.reveal(leader_commit);

        let (_, leader) = leader.decode(follower_output.into()).unwrap();

        let (follower_opening, follower) = follower.open();

        let _ = leader.validate(follower_opening.into()).unwrap();

        let malicious_leader_opening = Opening::new(&[0u8; 32]);

        let err = follower.verify(malicious_leader_opening).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }

    #[test]
    fn test_leader_fail_commit() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (_, leader, follower) = evaluated_pair(circ.clone());

        let (_, leader) = leader.commit();

        let malicious_leader_commit = Opening::new(&[0u8; 32]).commit();

        let (follower_output, follower) = follower.reveal(malicious_leader_commit);

        let (_, leader) = leader.decode(follower_output.into()).unwrap();

        let (follower_opening, follower) = follower.open();

        let leader = leader.validate(follower_opening.into()).unwrap();
        let leader_opening = leader.reveal();

        let err = follower.verify(leader_opening).unwrap_err();

        assert!(matches!(err, Error::PeerError(_)));
    }

    #[test]
    fn test_follower_fail_open_bad_delta() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (_, leader, follower) = evaluated_pair(circ.clone());

        let (leader_commit, leader) = leader.commit();
        let (follower_output, follower) = follower.reveal(leader_commit);

        let (_, leader) = leader.decode(follower_output.into()).unwrap();

        let (mut follower_opening, _) = follower.open();

        follower_opening.delta = Delta::from([0; 16]);

        let err = leader.validate(follower_opening.into()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit))
    }

    #[test]
    fn test_follower_fail_open_bad_decoding() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (_, leader, follower) = evaluated_pair(circ.clone());

        let (leader_commit, leader) = leader.commit();
        let (follower_output, follower) = follower.reveal(leader_commit);

        let (_, leader) = leader.decode(follower_output.into()).unwrap();

        let (mut follower_opening, _) = follower.open();

        // flip decoding bit
        follower_opening.input_decoding[0].decoding[0] =
            !follower_opening.input_decoding[0].decoding[0];

        let err = leader.validate(follower_opening.into()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit))
    }
}
