use crate::garble::{
    circuit::unchecked::{UncheckedCircuitOpening, UncheckedOutput},
    commitment::{HashCommitment, Opening},
    gc_state, ActiveInputLabelsSet, CircuitOpening, Error, FullInputLabelsSet, GarbledCircuit,
    LabelError, LabelsDigest,
};
use mpc_circuits::{Circuit, OutputValue};

use aes::{Aes128, NewBlockCipher};
use std::sync::Arc;

const SEND_OUTPUT_COMMITMENTS: bool = true;
const SEND_OUTPUT_DECODING: bool = true;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Generator {}
        impl Sealed for super::Evaluator {}
        impl Sealed for super::Commit {}
        impl Sealed for super::Decode {}
        impl Sealed for super::Validate {}
        impl Sealed for super::Reveal {}
    }

    pub trait State: sealed::Sealed {}

    #[derive(Debug)]
    pub struct Generator {
        pub(super) circ: Arc<Circuit>,
    }

    #[derive(Debug)]
    pub struct Evaluator {
        pub(super) gc_summary: GarbledCircuit<gc_state::FullSummary>,
    }

    #[derive(Debug)]
    pub struct Commit {
        pub(super) gc_summary: GarbledCircuit<gc_state::FullSummary>,
        pub(super) gc_cmp: GarbledCircuit<gc_state::Compressed>,
        pub(super) check: LabelsDigest,
    }

    #[derive(Debug)]
    pub struct Decode {
        pub(super) gc_cmp: GarbledCircuit<gc_state::Compressed>,
        pub(super) gc_summary: GarbledCircuit<gc_state::FullSummary>,
        pub(super) commit_opening: Opening,
    }

    #[derive(Debug)]
    pub struct Validate {
        pub(super) gc_cmp: GarbledCircuit<gc_state::Compressed>,
        pub(super) commit_opening: Opening,
    }

    #[derive(Debug)]
    pub struct Reveal {
        pub(super) commit_opening: Opening,
    }

    impl State for Generator {}
    impl State for Evaluator {}
    impl State for Commit {}
    impl State for Decode {}
    impl State for Validate {}
    impl State for Reveal {}
}

use state::*;

#[derive(Debug)]
pub struct DEAPLeader<S = Generator>
where
    S: State + std::fmt::Debug,
{
    state: S,
}

impl DEAPLeader {
    pub fn new(circ: Arc<Circuit>) -> DEAPLeader<Generator> {
        DEAPLeader {
            state: Generator { circ },
        }
    }
}

impl DEAPLeader<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        input_labels: FullInputLabelsSet,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DEAPLeader<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.state.circ.clone(), input_labels)?;

        self.from_full_circuit(gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        gc: GarbledCircuit<gc_state::Full>,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DEAPLeader<Evaluator>), Error> {
        Ok((
            gc.get_partial(SEND_OUTPUT_DECODING, SEND_OUTPUT_COMMITMENTS)?,
            DEAPLeader {
                state: Evaluator {
                    gc_summary: gc.summarize(),
                },
            },
        ))
    }
}

impl DEAPLeader<Evaluator> {
    /// Evaluate [`DEAPFollower`] circuit
    pub fn evaluate(
        self,
        gc: GarbledCircuit<gc_state::Partial>,
        input_labels: ActiveInputLabelsSet,
    ) -> Result<DEAPLeader<Commit>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let evaluated_gc = gc.evaluate(&cipher, input_labels)?;

        self.from_compressed_circuit(evaluated_gc.into_compressed())
    }

    /// Proceed to next state from externally evaluated and compressed circuit
    pub fn from_compressed_circuit(
        self,
        gc_cmp: GarbledCircuit<gc_state::Compressed>,
    ) -> Result<DEAPLeader<Commit>, Error> {
        let check = self.compute_output_check(&gc_cmp)?;

        Ok(DEAPLeader {
            state: Commit {
                gc_summary: self.state.gc_summary,
                gc_cmp,
                check,
            },
        })
    }

    fn compute_output_check(
        &self,
        gc_cmp: &GarbledCircuit<gc_state::Compressed>,
    ) -> Result<LabelsDigest, Error> {
        if !gc_cmp.has_decoding() {
            return Err(Error::PeerError(
                "Peer did not provide label decoding info".to_string(),
            ));
        }

        let output = gc_cmp.decode()?;

        // Using the output from the Follower's circuit, we select the expected output labels from our circuit
        let expected_labels = self
            .state
            .gc_summary
            .output_labels()
            .iter()
            .zip(output.iter())
            .map(|(labels, value)| labels.select(value.value()))
            .collect::<Result<Vec<_>, LabelError>>()?;

        Ok(LabelsDigest::new(
            &[
                expected_labels,
                gc_cmp.output_labels().get_labels().to_vec(),
            ]
            .concat(),
        ))
    }
}

impl DEAPLeader<Commit> {
    /// Commit to output
    pub fn commit(self) -> (HashCommitment, DEAPLeader<Decode>) {
        let commit_opening = Opening::new(&self.state.check.0);
        let commitment = commit_opening.commit();
        (
            commitment,
            DEAPLeader {
                state: Decode {
                    gc_summary: self.state.gc_summary,
                    gc_cmp: self.state.gc_cmp,
                    commit_opening,
                },
            },
        )
    }
}

impl DEAPLeader<Decode> {
    /// Decode the output sent from [`DEAPFollower`]
    pub fn decode(
        self,
        unchecked_output: UncheckedOutput,
    ) -> Result<(Vec<OutputValue>, DEAPLeader<Validate>), Error> {
        let output = unchecked_output.decode(
            &self.state.gc_summary.circ,
            self.state.gc_summary.output_labels().get_labels(),
        )?;

        Ok((
            output,
            DEAPLeader {
                state: Validate {
                    gc_cmp: self.state.gc_cmp,
                    commit_opening: self.state.commit_opening,
                },
            },
        ))
    }
}

impl DEAPLeader<Validate> {
    /// Validate [`DEAPFollower`]'s circuit was garbled honestly
    ///
    /// ** WARNING **
    /// [`DEAPLeader`] _must_ also verify the oblivious transfer for their input labels
    /// was performed honestly! We can not enforce this at this layer so proceed with caution.
    pub fn validate(self, unchecked: UncheckedCircuitOpening) -> Result<DEAPLeader<Reveal>, Error> {
        let opening = CircuitOpening::from_unchecked(&self.state.gc_cmp.circ, unchecked)?;
        self.state.gc_cmp.validate(opening)?;

        Ok(DEAPLeader {
            state: Reveal {
                commit_opening: self.state.commit_opening,
            },
        })
    }

    /// Return [`DEAPFollower`]'s garbled circuit to be validated externally
    /// and proceed to next state
    ///
    /// ** WARNING **
    /// [`DEAPLeader`] _must_ also verify the oblivious transfer for their input labels
    /// was performed honestly! We can not enforce this at this layer so proceed with caution.
    pub fn validate_external(
        self,
        unchecked: UncheckedCircuitOpening,
    ) -> Result<
        (
            CircuitOpening,
            GarbledCircuit<gc_state::Compressed>,
            DEAPLeader<Reveal>,
        ),
        Error,
    > {
        Ok((
            CircuitOpening::from_unchecked(&self.state.gc_cmp.circ, unchecked)?,
            self.state.gc_cmp,
            DEAPLeader {
                state: Reveal {
                    commit_opening: self.state.commit_opening,
                },
            },
        ))
    }
}

impl DEAPLeader<Reveal> {
    /// Open output commitment to [`DEAPFollower`]
    pub fn reveal(self) -> Opening {
        self.state.commit_opening
    }
}
