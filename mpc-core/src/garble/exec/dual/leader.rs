use crate::garble::{
    circuit::{state as gc_state, GarbledCircuit},
    commitment::{CommitmentOpening, HashCommitment},
    config::GarbleConfig,
    label::{ActiveOutputLabels, LabelsDigest},
    ActiveInputLabels, Delta, Error, FullInputLabels,
};
use mpc_circuits::InputValue;

use aes::{Aes128, NewBlockCipher};

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
    pub struct Generator {}

    #[derive(Debug)]
    pub struct Evaluator {
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
        pub(super) commit_opening: CommitmentOpening,
    }

    #[derive(Debug)]
    pub struct Reveal {
        pub(super) evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
        pub(super) commit_opening: CommitmentOpening,
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
    config: GarbleConfig,
    state: S,
}

impl DualExLeader {
    pub fn new(config: GarbleConfig) -> DualExLeader<Generator> {
        DualExLeader {
            config,
            state: Generator {},
        }
    }

    pub fn config(&self) -> &GarbleConfig {
        &self.config
    }
}

impl DualExLeader<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        inputs: &[InputValue],
        input_labels: &[FullInputLabels],
        delta: Delta,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DualExLeader<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.config.circ.clone(), delta, input_labels)?;

        self.from_full_circuit(inputs, gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        inputs: &[InputValue],
        gc: GarbledCircuit<gc_state::Full>,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DualExLeader<Evaluator>), Error> {
        Ok((
            gc.to_evaluator(inputs, true, false)?,
            DualExLeader {
                config: self.config,
                state: Evaluator { gc },
            },
        ))
    }
}

impl DualExLeader<Evaluator> {
    /// Evaluate [`DualExFollower`] circuit
    pub fn evaluate(
        self,
        gc: GarbledCircuit<gc_state::Partial>,
        input_labels: &[ActiveInputLabels],
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
            config: self.config,
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
            Vec::with_capacity(self.config.circ.output_count());
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
        let commit_opening = CommitmentOpening::new(&self.state.check.0);
        let commitment = commit_opening.commit();
        (
            commitment,
            DualExLeader {
                config: self.config,
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
            config: self.config,
            state: Reveal {
                evaluated_gc: self.state.evaluated_gc,
                commit_opening: self.state.commit_opening,
            },
        })
    }
}

impl DualExLeader<Reveal> {
    /// Open output commitment to [`DualExFollower`]
    pub fn reveal(self) -> (CommitmentOpening, GarbledCircuit<gc_state::Evaluated>) {
        (self.state.commit_opening, self.state.evaluated_gc)
    }
}
