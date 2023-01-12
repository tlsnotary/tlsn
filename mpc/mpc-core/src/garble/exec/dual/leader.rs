use crate::garble::{
    circuit::{state as gc_state, GarbledCircuit},
    commitment::{HashCommitment, Opening},
    label::{ActiveInputLabelsSet, ActiveOutputLabels, FullInputLabelsSet, LabelsDigest},
    Error,
};
use mpc_circuits::Circuit;

use aes::{Aes128, NewBlockCipher};
use std::sync::Arc;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Generator {}
        impl Sealed for super::Evaluator {}
        impl Sealed for super::Commit {}
        impl Sealed for super::Verify {}
        impl Sealed for super::Reveal {}
    }

    pub trait State: sealed::Sealed {}

    #[derive(Debug)]
    pub struct Generator {
        pub(super) circ: Arc<Circuit>,
    }

    #[derive(Debug)]
    pub struct Evaluator {
        pub(super) circ: Arc<Circuit>,
        pub(super) gc: GarbledCircuit<gc_state::Full>,
    }

    #[derive(Debug)]
    pub struct Commit {
        pub(super) evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
        pub(super) check: LabelsDigest,
    }

    #[derive(Debug)]
    pub struct Verify {
        pub(super) evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
        pub(super) check: LabelsDigest,
        pub(super) commit_opening: Opening,
    }

    #[derive(Debug)]
    pub struct Reveal {
        pub(super) evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
        pub(super) commit_opening: Opening,
    }

    impl State for Generator {}
    impl State for Evaluator {}
    impl State for Commit {}
    impl State for Verify {}
    impl State for Reveal {}
}

use state::*;

#[derive(Debug)]
pub struct DualExLeader<S = Generator>
where
    S: State + std::fmt::Debug,
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

impl DualExLeader<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        input_labels: FullInputLabelsSet,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DualExLeader<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.state.circ.clone(), input_labels)?;

        self.from_full_circuit(gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        gc: GarbledCircuit<gc_state::Full>,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DualExLeader<Evaluator>), Error> {
        Ok((
            gc.to_evaluator(true, false)?,
            DualExLeader {
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
        gc: GarbledCircuit<gc_state::Partial>,
        input_labels: ActiveInputLabelsSet,
    ) -> Result<DualExLeader<Commit>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let evaluated_gc = gc.evaluate(&cipher, input_labels)?;

        self.from_evaluated_circuit(evaluated_gc)
    }

    /// Proceed to next state from existing evaluated circuit
    pub fn from_evaluated_circuit(
        self,
        evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<DualExLeader<Commit>, Error> {
        let check = self.compute_output_check(&evaluated_gc)?;

        Ok(DualExLeader {
            state: Commit {
                evaluated_gc,
                check,
            },
        })
    }

    fn compute_output_check(
        &self,
        evaluated_gc: &GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<LabelsDigest, Error> {
        if !evaluated_gc.has_decoding() {
            return Err(Error::PeerError(
                "Peer did not provide label decoding info".to_string(),
            ));
        }

        let output = evaluated_gc.decode()?;

        let mut expected_labels: Vec<ActiveOutputLabels> =
            Vec::with_capacity(self.state.circ.output_count());
        // Here we use the output values from the peer's circuit to select the corresponding output labels from our garbled circuit
        for (labels, value) in self.state.gc.output_labels().iter().zip(output.iter()) {
            expected_labels.push(labels.select(value.value())?);
        }

        Ok(LabelsDigest::new(
            &[expected_labels, evaluated_gc.output_labels().to_vec()].concat(),
        ))
    }
}

impl DualExLeader<Commit> {
    /// Commit to output
    pub fn commit(self) -> (HashCommitment, DualExLeader<Verify>) {
        let commit_opening = Opening::new(&self.state.check.0);
        let commitment = commit_opening.commit();
        (
            commitment,
            DualExLeader {
                state: Verify {
                    evaluated_gc: self.state.evaluated_gc,
                    check: self.state.check,
                    commit_opening,
                },
            },
        )
    }
}

impl DualExLeader<Verify> {
    /// Check [`DualExFollower`] output matches expected
    pub fn check(self, check: LabelsDigest) -> Result<DualExLeader<Reveal>, Error> {
        // If this fails then the peer was cheating and your private inputs were potentially leaked
        // with a probability of 1/(2^n), where n is the number of potentially leaked bits, and you
        // should call the police immediately
        if check != self.state.check {
            return Err(Error::PeerError(
                "Peer sent invalid output check".to_string(),
            ));
        }

        Ok(DualExLeader {
            state: Reveal {
                evaluated_gc: self.state.evaluated_gc,
                commit_opening: self.state.commit_opening,
            },
        })
    }
}

impl DualExLeader<Reveal> {
    /// Open output commitment to [`DualExFollower`]
    pub fn reveal(self) -> (Opening, GarbledCircuit<gc_state::Evaluated>) {
        (self.state.commit_opening, self.state.evaluated_gc)
    }
}
