use crate::garble::{
    circuit::unchecked::{UncheckedCircuitOpening, UncheckedOutput},
    commitment::{CommitmentOpening, HashCommitment},
    config::GarbleConfig,
    gc_state, ActiveInputLabels, CircuitOpening, Delta, Error, FullInputLabels, GarbledCircuit,
    LabelError, LabelsDigest,
};
use mpc_circuits::{InputValue, OutputValue};

use aes::{Aes128, NewBlockCipher};

const SEND_OUTPUT_COMMITMENTS: bool = true;
const SEND_OUTPUT_DECODING: bool = true;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Generator {}
        impl Sealed for super::Evaluator {}
        impl Sealed for super::Compress {}
        impl Sealed for super::Commit {}
        impl Sealed for super::Decode {}
        impl Sealed for super::Validate {}
        impl Sealed for super::Reveal {}
    }

    pub trait State: sealed::Sealed {}

    #[derive(Debug)]
    pub struct Generator {}

    #[derive(Debug)]
    pub struct Evaluator {
        pub(super) gc_summary: GarbledCircuit<gc_state::Summary>,
    }

    #[derive(Debug)]
    pub struct Compress {
        pub(super) gc_summary: GarbledCircuit<gc_state::Summary>,
        pub(super) check: LabelsDigest,
    }

    #[derive(Debug)]
    pub struct Commit {
        pub(super) gc_summary: GarbledCircuit<gc_state::Summary>,
        pub(super) gc_cmp: GarbledCircuit<gc_state::Compressed>,
        pub(super) check: LabelsDigest,
    }

    #[derive(Debug)]
    pub struct Decode {
        pub(super) gc_cmp: GarbledCircuit<gc_state::Compressed>,
        pub(super) gc_summary: GarbledCircuit<gc_state::Summary>,
        pub(super) commit_opening: CommitmentOpening,
    }

    #[derive(Debug)]
    pub struct Validate {
        pub(super) gc_cmp: GarbledCircuit<gc_state::Compressed>,
        pub(super) commit_opening: CommitmentOpening,
    }

    #[derive(Debug)]
    pub struct Reveal {
        pub(super) commit_opening: CommitmentOpening,
    }

    impl State for Generator {}
    impl State for Evaluator {}
    impl State for Compress {}
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
    config: GarbleConfig,
    state: S,
}

impl DEAPLeader {
    pub fn new(config: GarbleConfig) -> DEAPLeader<Generator> {
        DEAPLeader {
            config,
            state: Generator {},
        }
    }
}

impl DEAPLeader<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        inputs: &[InputValue],
        input_labels: &[FullInputLabels],
        delta: Delta,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DEAPLeader<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.config.circ.clone(), delta, input_labels)?;

        self.from_full_circuit(inputs, gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        inputs: &[InputValue],
        gc: GarbledCircuit<gc_state::Full>,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DEAPLeader<Evaluator>), Error> {
        Ok((
            gc.to_evaluator(inputs, SEND_OUTPUT_DECODING, SEND_OUTPUT_COMMITMENTS)?,
            DEAPLeader {
                config: self.config,
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
        input_labels: &[ActiveInputLabels],
    ) -> Result<DEAPLeader<Commit>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let evaluated_gc = gc.evaluate(&cipher, input_labels)?;

        self.from_compressed_circuit(evaluated_gc.compress())
    }

    /// Proceed to next state from externally evaluated and compressed circuit
    pub fn from_compressed_circuit(
        self,
        gc_cmp: GarbledCircuit<gc_state::Compressed>,
    ) -> Result<DEAPLeader<Commit>, Error> {
        let check = self.compute_output_check(&gc_cmp)?;

        Ok(DEAPLeader {
            config: self.config,
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
            &[expected_labels, gc_cmp.output_labels().to_vec()].concat(),
        ))
    }
}

impl DEAPLeader<Compress> {
    /// Compress [`DEAPFollower`]'s circuit
    pub fn compress(self, gc_evaluated: GarbledCircuit<gc_state::Evaluated>) -> DEAPLeader<Commit> {
        self.from_compressed_circuit(gc_evaluated.compress())
    }

    /// Proceed to next state using compressed garbled circuit
    pub fn from_compressed_circuit(
        self,
        gc_cmp: GarbledCircuit<gc_state::Compressed>,
    ) -> DEAPLeader<Commit> {
        DEAPLeader {
            config: self.config,
            state: Commit {
                gc_summary: self.state.gc_summary,
                gc_cmp,
                check: self.state.check,
            },
        }
    }
}

impl DEAPLeader<Commit> {
    /// Commit to output
    pub fn commit(self) -> (HashCommitment, DEAPLeader<Decode>) {
        let commit_opening = CommitmentOpening::new(&self.state.check.0);
        let commitment = commit_opening.commit();
        (
            commitment,
            DEAPLeader {
                config: self.config,
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
            self.state.gc_summary.output_labels(),
        )?;

        Ok((
            output,
            DEAPLeader {
                config: self.config,
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
            config: self.config,
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
                config: self.config,
                state: Reveal {
                    commit_opening: self.state.commit_opening,
                },
            },
        ))
    }
}

impl DEAPLeader<Reveal> {
    /// Open output commitment to [`DEAPFollower`]
    pub fn reveal(self) -> CommitmentOpening {
        self.state.commit_opening
    }
}
