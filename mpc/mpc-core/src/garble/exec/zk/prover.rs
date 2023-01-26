use crate::garble::{
    circuit::{
        state as gc_state,
        unchecked::{UncheckedCircuitOpening, UncheckedGarbledCircuit},
        GarbledCircuit,
    },
    commitment::{HashCommitment, Opening},
    label::ActiveInputSet,
    CircuitOpening, Error, LabelsDigest,
};
use mpc_circuits::Circuit;

use aes::{Aes128, NewBlockCipher};
use std::sync::Arc;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Evaluator {}
        impl Sealed for super::Commit {}
        impl Sealed for super::Validate {}
        impl Sealed for super::Reveal {}
    }

    pub trait State: sealed::Sealed {}

    #[derive(Debug)]
    pub struct Evaluator {}

    #[derive(Debug)]
    pub struct Commit {
        pub(super) gc: GarbledCircuit<gc_state::Compressed>,
    }

    #[derive(Debug)]
    pub struct Validate {
        pub(super) gc: GarbledCircuit<gc_state::Compressed>,
        /// Opening to the output commitment
        pub(super) commit_opening: Opening,
    }

    #[derive(Debug)]
    pub struct Reveal {
        pub(super) gc: GarbledCircuit<gc_state::Output>,
        /// Opening to the output commitment
        pub(super) commit_opening: Opening,
    }

    impl State for Evaluator {}
    impl State for Commit {}
    impl State for Validate {}
    impl State for Reveal {}
}

use state::*;

#[derive(Debug)]
pub struct Prover<S = Evaluator>
where
    S: State,
{
    circ: Arc<Circuit>,
    state: S,
}

impl Prover {
    pub fn new(circ: Arc<Circuit>) -> Prover<Evaluator> {
        Prover {
            circ,
            state: Evaluator {},
        }
    }
}

impl Prover<Evaluator> {
    /// Evaluate [`Verifier`] circuit
    pub fn evaluate(
        self,
        unchecked_gc: UncheckedGarbledCircuit,
        input_labels: ActiveInputSet,
    ) -> Result<Prover<Commit>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.circ.clone(), unchecked_gc)?;

        Ok(Prover {
            circ: self.circ,
            state: Commit {
                gc: gc.evaluate(&cipher, input_labels)?.into_compressed(),
            },
        })
    }

    /// Proceeds to next state using evaluated and compressed circuit from outer context
    pub fn from_compressed_circuit(
        self,
        gc: GarbledCircuit<gc_state::Compressed>,
    ) -> Prover<Commit> {
        Prover {
            circ: self.circ,
            state: Commit { gc },
        }
    }
}

impl Prover<Commit> {
    /// Commit to [`Verifier`] circuit
    pub fn commit(self) -> (HashCommitment, Prover<Validate>) {
        // Compute hash of active output labels
        let output_digest = LabelsDigest::new(
            self.state
                .gc
                .output_labels()
                .iter()
                .map(|labels| labels.iter())
                .flatten(),
        );
        let commit_opening = Opening::new(&output_digest.0);
        let commit = commit_opening.commit();

        (
            commit,
            Prover {
                circ: self.circ,
                state: Validate {
                    gc: self.state.gc,
                    commit_opening,
                },
            },
        )
    }
}

impl Prover<Validate> {
    /// Validate [`Verifier`]'s circuit was garbled honestly
    ///
    /// ** WARNING **
    /// [`Prover`] _must_ also verify the oblivious transfer for their input labels
    /// was performed honestly! We can not enforce this at this layer so proceed with caution.
    pub fn validate(self, unchecked: UncheckedCircuitOpening) -> Result<Prover<Reveal>, Error> {
        let opening = CircuitOpening::from_unchecked(&self.state.gc.circ, unchecked)?;
        self.state.gc.validate(opening)?;

        Ok(Prover {
            circ: self.circ,
            state: Reveal {
                gc: self.state.gc.get_output(),
                commit_opening: self.state.commit_opening,
            },
        })
    }

    /// Return [`Verifier`]'s garbled circuit to be validated externally
    /// and proceed to next state
    ///
    /// ** WARNING **
    /// [`Prover`] _must_ also verify the oblivious transfer for their input labels
    /// was performed honestly! We can not enforce this at this layer so proceed with caution.
    pub fn validate_external(
        self,
        unchecked: UncheckedCircuitOpening,
    ) -> Result<
        (
            CircuitOpening,
            GarbledCircuit<gc_state::Compressed>,
            Prover<Reveal>,
        ),
        Error,
    > {
        let output = self.state.gc.get_output();

        Ok((
            CircuitOpening::from_unchecked(&self.circ, unchecked)?,
            self.state.gc,
            Prover {
                circ: self.circ,
                state: Reveal {
                    gc: output,
                    commit_opening: self.state.commit_opening,
                },
            },
        ))
    }
}

impl Prover<Reveal> {
    /// Open output commitment to [`Verifier`]
    pub fn reveal(self) -> (Opening, GarbledCircuit<gc_state::Output>) {
        (self.state.commit_opening, self.state.gc)
    }
}
