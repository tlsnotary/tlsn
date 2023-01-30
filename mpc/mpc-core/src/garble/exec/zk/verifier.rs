use crate::garble::{
    circuit::{state as gc_state, unchecked::UncheckedOutput, GarbledCircuit},
    commitment::{HashCommitment, Opening},
    label::FullInputSet,
    CircuitOpening, Error, LabelsDigest,
};
use mpc_circuits::{Circuit, OutputValue};

use aes::{Aes128, NewBlockCipher};
use std::sync::Arc;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Generator {}
        impl Sealed for super::StoreCommit {}
        impl Sealed for super::Open {}
        impl Sealed for super::Verify {}
    }

    pub trait State: sealed::Sealed {}

    #[derive(Debug)]
    pub struct Generator {}

    #[derive(Debug)]
    pub struct StoreCommit {
        pub(super) gc: GarbledCircuit<gc_state::FullSummary>,
    }

    #[derive(Debug)]
    pub struct Open {
        pub(super) gc: GarbledCircuit<gc_state::FullSummary>,
        /// Prover's commitment to the output
        pub(super) commitment: HashCommitment,
    }

    #[derive(Debug)]
    pub struct Verify {
        pub(super) gc: GarbledCircuit<gc_state::FullSummary>,
        /// Prover's commitment to the output
        pub(super) commitment: HashCommitment,
    }

    impl State for Generator {}
    impl State for StoreCommit {}
    impl State for Open {}
    impl State for Verify {}
}

use state::*;

#[derive(Debug)]
pub struct Verifier<S = Generator>
where
    S: State,
{
    circ: Arc<Circuit>,
    state: S,
}

impl Verifier {
    pub fn new(circ: Arc<Circuit>) -> Verifier<Generator> {
        Verifier {
            circ,
            state: Generator {},
        }
    }
}

impl Verifier<Generator> {
    /// Garble circuit and send to `Prover`
    pub fn garble(
        self,
        input_labels: FullInputSet,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, Verifier<StoreCommit>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.circ.clone(), input_labels)?;

        self.from_full_circuit(gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        gc: GarbledCircuit<gc_state::Full>,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, Verifier<StoreCommit>), Error> {
        Ok((
            gc.get_partial(true, false)?,
            Verifier {
                circ: self.circ,
                state: StoreCommit {
                    gc: gc.into_summary(),
                },
            },
        ))
    }
}

impl Verifier<StoreCommit> {
    /// Stores output commitment
    pub fn store_commit(self, commitment: HashCommitment) -> Verifier<Open> {
        Verifier {
            circ: self.circ,
            state: Open {
                gc: self.state.gc,
                commitment,
            },
        }
    }
}

impl Verifier<Open> {
    /// Opens garbled circuit to the [`Prover`]
    pub fn open(self) -> (CircuitOpening, Verifier<Verify>) {
        let opening = self.state.gc.open();

        (
            opening,
            Verifier {
                circ: self.circ,
                state: Verify {
                    gc: self.state.gc,
                    commitment: self.state.commitment,
                },
            },
        )
    }
}

impl Verifier<Verify> {
    /// Verifies that the [`Prover`] committed to an authentic output
    pub fn verify(
        self,
        commit_opening: Opening,
        unchecked_output: UncheckedOutput,
    ) -> Result<Vec<OutputValue>, Error> {
        let full_output_labels = self.state.gc.output_labels().get_groups();

        // Verifies that the output is authentic
        let output = unchecked_output.decode(&self.circ, full_output_labels)?;

        // Select active labels corresponding to the authentic output
        let active_output_labels = full_output_labels
            .iter()
            .zip(output.iter())
            .map(|(labels, value)| labels.select(value.value()))
            .collect::<Result<Vec<_>, _>>()?;

        // Compute hash of active output labels
        let output_digest = LabelsDigest::new(
            active_output_labels
                .iter()
                .map(|labels| labels.iter())
                .flatten(),
        );

        // Opening corresponds to the output commitment the Prover sent earlier
        self.state.commitment.verify(&commit_opening)?;

        // Verify the commitment corresponds to the output we received
        commit_opening.verify_message(&output_digest.0)?;

        Ok(output)
    }
}
