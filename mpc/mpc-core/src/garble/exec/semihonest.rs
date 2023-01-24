//! An implementation of semi-honest mode which provides authenticity and privacy assurances to the [`SemiHonestLeader`]
//! but not to the [`SemiHonestFollower`]. The leader is capable of garbling the circuit maliciously
//! which may result in the private inputs of the follower being leaked. Additonally, the follower
//! does not know whether the output decoding provided by the leader is authentic. Thus, the follower
//! can not rely on this execution mode for correctness or privacy.
use crate::garble::{
    circuit::{
        state as gc_state,
        unchecked::{UncheckedGarbledCircuit, UncheckedOutput},
        GarbledCircuit,
    },
    label::{ActiveInputSet, FullInputSet},
    Error,
};
use mpc_circuits::{Circuit, OutputValue};

use aes::{Aes128, NewBlockCipher};
use std::sync::Arc;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Generator {}
        impl Sealed for super::Evaluator {}
        impl Sealed for super::Decode {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Generator {
        pub(super) circ: Arc<Circuit>,
    }

    pub struct Evaluator {
        pub(super) circ: Arc<Circuit>,
    }

    pub struct Decode {
        pub(super) gc: GarbledCircuit<gc_state::FullSummary>,
    }

    impl State for Generator {}
    impl State for Evaluator {}
    impl State for Decode {}
}

use state::*;

pub struct SemiHonestLeader<S = Generator>
where
    S: State,
{
    state: S,
}

pub struct SemiHonestFollower<S = Evaluator>
where
    S: State,
{
    state: S,
}

impl SemiHonestLeader {
    pub fn new(circ: Arc<Circuit>) -> SemiHonestLeader<Generator> {
        SemiHonestLeader {
            state: Generator { circ },
        }
    }
}

impl SemiHonestFollower {
    pub fn new(circ: Arc<Circuit>) -> SemiHonestFollower<Evaluator> {
        SemiHonestFollower {
            state: Evaluator { circ },
        }
    }
}

impl SemiHonestLeader<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        input_labels: FullInputSet,
        reveal_output: bool,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, SemiHonestLeader<Decode>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.state.circ.clone(), input_labels)?;

        self.from_full_circuit(gc, reveal_output)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        gc: GarbledCircuit<gc_state::Full>,
        reveal_output: bool,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, SemiHonestLeader<Decode>), Error> {
        Ok((
            gc.get_partial(reveal_output, true)?,
            SemiHonestLeader {
                state: Decode { gc: gc.summarize() },
            },
        ))
    }
}

impl SemiHonestFollower<Evaluator> {
    /// Evaluate [`SemiHonestLeader`] circuit
    pub fn evaluate(
        self,
        unchecked_gc: UncheckedGarbledCircuit,
        input_labels: ActiveInputSet,
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::<gc_state::Partial>::from_unchecked(
            self.state.circ.clone(),
            unchecked_gc,
        )?;

        // The generator must send commitments to the output labels to mitigate
        // some types of malicious garbling
        if !gc.has_output_commitments() {
            return Err(Error::PeerError(
                "Peer did not send output commitments with garbled circuit".to_string(),
            ));
        }

        Ok(gc.evaluate(&cipher, input_labels)?)
    }
}

impl SemiHonestLeader<Decode> {
    /// Authenticates output wire labels sent by the peer and decodes the output
    pub fn decode(self, unchecked: UncheckedOutput) -> Result<Vec<OutputValue>, Error> {
        unchecked.decode(
            &self.state.gc.circ,
            &self.state.gc.output_labels().get_groups(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{garble::Label, Block};

    use super::*;
    use mpc_circuits::{Value, WireGroup, ADDER_64};
    use rand::thread_rng;

    #[test]
    fn test_semi_honest_success() {
        let mut rng = thread_rng();
        let circ = Circuit::load_bytes(ADDER_64).unwrap();

        let leader = SemiHonestLeader::new(circ.clone());
        let follower = SemiHonestFollower::new(circ.clone());

        let leader_input = circ.input(0).unwrap().to_value(0u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(1u64).unwrap();

        let input_labels = FullInputSet::generate(&mut rng, &circ, None);

        let (gc_partial, leader) = leader.garble(input_labels.clone(), true).unwrap();

        let leader_labels = input_labels[0].select(leader_input.value()).unwrap();
        let follower_labels = input_labels[1].select(follower_input.value()).unwrap();

        let active_labels = ActiveInputSet::new(vec![leader_labels, follower_labels]).unwrap();

        let gc_ev = follower.evaluate(gc_partial.into(), active_labels).unwrap();

        let gc_output = gc_ev.get_output();

        let output = leader.decode(gc_output.into()).unwrap();

        assert_eq!(*output[0].value(), Value::U64(1u64));
    }

    #[test]
    fn test_semi_honest_fail_ev_malicious_labels() {
        let mut rng = thread_rng();
        let circ = Circuit::load_bytes(ADDER_64).unwrap();

        let leader = SemiHonestLeader::new(circ.clone());
        let follower = SemiHonestFollower::new(circ.clone());

        let leader_input = circ.input(0).unwrap().to_value(0u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(1u64).unwrap();

        let input_labels = FullInputSet::generate(&mut rng, &circ, None);

        let (gc_partial, leader) = leader.garble(input_labels.clone(), true).unwrap();

        let leader_labels = input_labels[0].select(leader_input.value()).unwrap();
        let follower_labels = input_labels[1].select(follower_input.value()).unwrap();

        let active_labels = ActiveInputSet::new(vec![leader_labels, follower_labels]).unwrap();

        let gc_ev = follower.evaluate(gc_partial.into(), active_labels).unwrap();

        let mut gc_output = gc_ev.get_output();

        // Insert a bogus output label
        gc_output.state.output_labels[0].set(0, Label::new(Block::new(0)));

        let error = leader.decode(gc_output.into()).unwrap_err();

        assert!(matches!(error, Error::LabelError(_)));
    }

    #[test]
    fn test_semi_honest_fail_malicious_commitments() {
        let mut rng = thread_rng();
        let circ = Circuit::load_bytes(ADDER_64).unwrap();

        let leader = SemiHonestLeader::new(circ.clone());
        let follower = SemiHonestFollower::new(circ.clone());

        let leader_input = circ.input(0).unwrap().to_value(0u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(1u64).unwrap();

        let input_labels = FullInputSet::generate(&mut rng, &circ, None);

        let (mut gc_partial, _) = leader.garble(input_labels.clone(), true).unwrap();

        // Insert bogus output label commitments
        gc_partial.state.commitments.as_mut().unwrap()[0].commitments[0][0] = Block::new(0);
        gc_partial.state.commitments.as_mut().unwrap()[0].commitments[0][1] = Block::new(1);

        let leader_labels = input_labels[0].select(leader_input.value()).unwrap();
        let follower_labels = input_labels[1].select(follower_input.value()).unwrap();

        let active_labels = ActiveInputSet::new(vec![leader_labels, follower_labels]).unwrap();

        let error = follower
            .evaluate(gc_partial.into(), active_labels)
            .unwrap_err();

        assert!(matches!(error, Error::LabelError(_)));
    }
}
