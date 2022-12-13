use crate::garble::{
    circuit::{Evaluated, Full, GarbledCircuit, Partial},
    commitment::{HashCommitment, Opening},
    label::{OutputCheck, OutputLabels},
    Delta, Error, InputLabels, WireLabel, WireLabelPair,
};
use mpc_circuits::{Circuit, InputValue};

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
        pub(super) gc: GarbledCircuit<Full>,
    }

    #[derive(Debug)]
    pub struct Reveal {
        pub(super) evaluated_gc: GarbledCircuit<Evaluated>,
        pub(super) check: OutputCheck,
    }

    #[derive(Debug)]
    pub struct Verify {
        pub(super) evaluated_gc: GarbledCircuit<Evaluated>,
        pub(super) check: OutputCheck,
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
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<(GarbledCircuit<Partial>, DualExFollower<Evaluator>), Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let gc = GarbledCircuit::generate(&cipher, self.state.circ.clone(), delta, input_labels)?;

        self.from_full_circuit(inputs, gc)
    }

    /// Proceed to next state from existing garbled circuit
    pub fn from_full_circuit(
        self,
        inputs: &[InputValue],
        gc: GarbledCircuit<Full>,
    ) -> Result<(GarbledCircuit<Partial>, DualExFollower<Evaluator>), Error> {
        Ok((
            gc.to_evaluator(inputs, true, false),
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
        gc: GarbledCircuit<Partial>,
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<DualExFollower<Reveal>, Error> {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let evaluated_gc = gc.evaluate(&cipher, input_labels)?;

        self.from_evaluated_circuit(evaluated_gc)
    }

    /// Proceed to next state from existing evaluated circuit
    pub fn from_evaluated_circuit(
        self,
        evaluated_gc: GarbledCircuit<Evaluated>,
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
        evaluated_gc: &GarbledCircuit<Evaluated>,
    ) -> Result<OutputCheck, Error> {
        if !evaluated_gc.has_encoding() {
            return Err(Error::PeerError(
                "Peer did not provide label encoding".to_string(),
            ));
        }

        let output = evaluated_gc.decode()?;

        let mut expected_labels: Vec<OutputLabels<WireLabel>> =
            Vec::with_capacity(self.state.circ.output_count());
        // Here we use the output values from the peer's circuit to select the corresponding output labels from our garbled circuit
        for (labels, value) in self.state.gc.output_labels().iter().zip(output.iter()) {
            expected_labels.push(labels.select(value)?);
        }

        Ok(OutputCheck::new((
            &evaluated_gc.output_labels(),
            &expected_labels,
        )))
    }
}

impl DualExFollower<Reveal> {
    /// Receive commitment from [`DualExLeader`] and reveal [`DualExFollower`] check
    pub fn reveal(self, commit: HashCommitment) -> (OutputCheck, DualExFollower<Verify>) {
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
    pub fn verify(self, opening: Opening) -> Result<GarbledCircuit<Evaluated>, Error> {
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
