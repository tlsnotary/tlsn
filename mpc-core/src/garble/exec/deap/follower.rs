use crate::garble::{
    commitment::{CommitmentOpening, HashCommitment},
    config::GarbleConfig,
    gc_state, ActiveInputLabels, CircuitOpening, Delta, Error, FullInputLabels, GarbledCircuit,
    LabelError, LabelsDigest,
};
use mpc_circuits::{InputValue, OutputValue};

use aes::{Aes128, NewBlockCipher};

const SEND_OUTPUT_COMMITMENTS: bool = false;
const SEND_OUTPUT_DECODING: bool = true;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Generator {}
        impl Sealed for super::Evaluator {}
        impl Sealed for super::Reveal {}
        impl Sealed for super::Open {}
        impl Sealed for super::Verify {}
    }

    pub trait State: sealed::Sealed {}

    #[derive(Debug)]
    pub struct Generator {}

    #[derive(Debug)]
    pub struct Evaluator {
        pub(super) gc: GarbledCircuit<gc_state::Full>,
    }

    #[derive(Debug)]
    pub struct Reveal {
        pub(super) gc_output: GarbledCircuit<gc_state::Output>,
        pub(super) opening: CircuitOpening,
        pub(super) check: LabelsDigest,
    }

    #[derive(Debug)]
    pub struct Open {
        pub(super) opening: CircuitOpening,
        pub(super) check: LabelsDigest,
        pub(super) commit: HashCommitment,
    }

    #[derive(Debug)]
    pub struct Verify {
        pub(super) check: LabelsDigest,
        pub(super) commit: HashCommitment,
    }

    impl State for Generator {}
    impl State for Evaluator {}
    impl State for Reveal {}
    impl State for Open {}
    impl State for Verify {}
}

use state::*;

#[derive(Debug)]
pub struct DEAPFollower<S = Generator>
where
    S: State + std::fmt::Debug,
{
    config: GarbleConfig,
    state: S,
}

impl DEAPFollower {
    pub fn new(config: GarbleConfig) -> DEAPFollower<Generator> {
        DEAPFollower {
            config,
            state: Generator {},
        }
    }
}

impl DEAPFollower<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        inputs: &[InputValue],
        input_labels: &[FullInputLabels],
        delta: Delta,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DEAPFollower<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.config.circ.clone(), delta, input_labels)?;

        self.from_full_circuit(inputs, gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        inputs: &[InputValue],
        gc: GarbledCircuit<gc_state::Full>,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DEAPFollower<Evaluator>), Error> {
        Ok((
            gc.to_evaluator(inputs, SEND_OUTPUT_DECODING, SEND_OUTPUT_COMMITMENTS)?,
            DEAPFollower {
                config: self.config,
                state: Evaluator { gc },
            },
        ))
    }
}

impl DEAPFollower<Evaluator> {
    /// Evaluate [`DEAPLeader`] circuit
    pub fn evaluate(
        self,
        gc: GarbledCircuit<gc_state::Partial>,
        input_labels: &[ActiveInputLabels],
    ) -> Result<(Vec<OutputValue>, DEAPFollower<Reveal>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc_evaluated = gc.evaluate(&cipher, input_labels)?;

        self.from_evaluated_circuit(gc_evaluated)
    }

    /// Proceed to next state from existing evaluated circuit
    pub fn from_evaluated_circuit(
        self,
        gc_evaluated: GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<(Vec<OutputValue>, DEAPFollower<Reveal>), Error> {
        let (purported_output, check) = self.compute_output_check(&gc_evaluated)?;

        Ok((
            purported_output,
            DEAPFollower {
                config: self.config,
                state: Reveal {
                    gc_output: gc_evaluated.to_output(),
                    opening: self.state.gc.open(),
                    check,
                },
            },
        ))
    }

    fn compute_output_check(
        &self,
        gc_evaluated: &GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<(Vec<OutputValue>, LabelsDigest), Error> {
        if !gc_evaluated.has_decoding() {
            return Err(Error::PeerError(
                "Peer did not provide label decoding info".to_string(),
            ));
        }

        let output = gc_evaluated.decode()?;

        // Using the output from the Leaders's circuit, we select the expected output labels from our circuit
        let expected_labels = self
            .state
            .gc
            .output_labels()
            .iter()
            .zip(output.iter())
            .map(|(labels, value)| labels.select(value.value()))
            .collect::<Result<Vec<_>, LabelError>>()?;

        Ok((
            output,
            LabelsDigest::new(&[gc_evaluated.output_labels().to_vec(), expected_labels].concat()),
        ))
    }
}

impl DEAPFollower<Reveal> {
    /// Receive commitment from [`DEAPLeader`] and reveal output
    pub fn reveal(
        self,
        commit: HashCommitment,
    ) -> (GarbledCircuit<gc_state::Output>, DEAPFollower<Open>) {
        (
            self.state.gc_output,
            DEAPFollower {
                config: self.config,
                state: Open {
                    opening: self.state.opening,
                    check: self.state.check,
                    commit,
                },
            },
        )
    }
}

impl DEAPFollower<Open> {
    /// Opens circuit to [`DEAPLeader`]
    pub fn open(self) -> (CircuitOpening, DEAPFollower<Verify>) {
        (
            self.state.opening,
            DEAPFollower {
                config: self.config,
                state: Verify {
                    check: self.state.check,
                    commit: self.state.commit,
                },
            },
        )
    }
}

impl DEAPFollower<Verify> {
    /// Check [`DEAPLeader`] output commitment matches expected
    pub fn verify(self, opening: CommitmentOpening) -> Result<(), Error> {
        // If this fails then the peer was cheating and your private inputs were potentially leaked
        // and you should call the police immediately
        if opening.message() != self.state.check.0 {
            return Err(Error::PeerError(
                "Peer sent invalid output check".to_string(),
            ));
        }

        // If this fails then the peer was definitely cheating
        self.state.commit.verify(&opening).map_err(|_| {
            Error::PeerError(
                "Peer sent output check which does not match previous commitment".to_string(),
            )
        })?;

        Ok(())
    }
}
