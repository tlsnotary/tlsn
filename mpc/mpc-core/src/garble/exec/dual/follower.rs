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
        impl Sealed for super::Reveal {}
        impl Sealed for super::Verify {}
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
    pub struct Reveal {
        pub(super) evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
        pub(super) check: LabelsDigest,
    }

    #[derive(Debug)]
    pub struct Verify {
        pub(super) evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
        pub(super) check: LabelsDigest,
        pub(super) commit: HashCommitment,
    }

    impl State for Generator {}
    impl State for Evaluator {}
    impl State for Reveal {}
    impl State for Verify {}
}

use state::*;

#[derive(Debug)]
pub struct DualExFollower<S = Generator>
where
    S: State + std::fmt::Debug,
{
    state: S,
}

impl DualExFollower {
    pub fn new(circ: Arc<Circuit>) -> DualExFollower<Generator> {
        DualExFollower {
            state: Generator { circ },
        }
    }
}

impl DualExFollower<Generator> {
    /// Garble circuit and send to peer
    pub fn garble(
        self,
        input_labels: FullInputLabelsSet,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DualExFollower<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.state.circ.clone(), input_labels)?;

        self.from_full_circuit(gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        gc: GarbledCircuit<gc_state::Full>,
    ) -> Result<(GarbledCircuit<gc_state::Partial>, DualExFollower<Evaluator>), Error> {
        Ok((
            gc.to_evaluator(true, false)?,
            DualExFollower {
                state: Evaluator {
                    gc,
                    circ: self.state.circ,
                },
            },
        ))
    }
}

impl DualExFollower<Evaluator> {
    /// Evaluate [`DualExLeader`] circuit
    pub fn evaluate(
        self,
        gc: GarbledCircuit<gc_state::Partial>,
        input_labels: ActiveInputLabelsSet,
    ) -> Result<DualExFollower<Reveal>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let evaluated_gc = gc.evaluate(&cipher, input_labels)?;

        self.from_evaluated_circuit(evaluated_gc)
    }

    /// Proceed to next state from existing evaluated circuit
    pub fn from_evaluated_circuit(
        self,
        evaluated_gc: GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<DualExFollower<Reveal>, Error> {
        let check = self.compute_output_check(&evaluated_gc)?;

        Ok(DualExFollower {
            state: Reveal {
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
            &[evaluated_gc.output_labels().to_vec(), expected_labels].concat(),
        ))
    }
}

impl DualExFollower<Reveal> {
    /// Receive commitment from [`DualExLeader`] and reveal [`DualExFollower`] check
    pub fn reveal(self, commit: HashCommitment) -> (LabelsDigest, DualExFollower<Verify>) {
        (
            self.state.check.clone(),
            DualExFollower {
                state: Verify {
                    evaluated_gc: self.state.evaluated_gc,
                    check: self.state.check,
                    commit,
                },
            },
        )
    }
}

impl DualExFollower<Verify> {
    /// Check [`DualExLeader`] output commitment matches expected
    pub fn verify(self, opening: Opening) -> Result<GarbledCircuit<gc_state::Evaluated>, Error> {
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

        Ok(self.state.evaluated_gc)
    }
}
