//! An implementation of malicious-secure zero-knowledge proofs using Garbled Circuits.
//!
//! This protocol allows a Prover to prove in zero-knowledge the output of a circuit to a Verifier
//! without leaking any information about their private inputs. The Verifier can also provide
//! private inputs which are revealed after the Prover commits to the output of the circuit.
//!
//! ** Warning **
//!
//! This protocol requires the use of committed OT, which is not enforced by the type system in this
//! core crate.

mod config;
mod prover;
mod verifier;

pub use config::{
    ProverConfig, ProverConfigBuilder, ProverConfigBuilderError, VerifierConfig,
    VerifierConfigBuilder, VerifierConfigBuilderError,
};
pub use prover::{state as prover_state, Prover};
pub use verifier::{state as verifier_state, Verifier};

use crate::garble::{gc_state, GarbledCircuit};

#[derive(Debug, Clone)]
pub struct ProverSummary {
    evaluated: GarbledCircuit<gc_state::EvaluatedSummary>,
}

impl ProverSummary {
    pub fn new(evaluated: GarbledCircuit<gc_state::EvaluatedSummary>) -> Self {
        Self { evaluated }
    }

    pub fn get_evaluator_summary(&self) -> &GarbledCircuit<gc_state::EvaluatedSummary> {
        &self.evaluated
    }
}

#[derive(Debug, Clone)]
pub struct VerifierSummary {
    generated: GarbledCircuit<gc_state::FullSummary>,
}

impl VerifierSummary {
    pub fn new(generated: GarbledCircuit<gc_state::FullSummary>) -> Self {
        Self { generated }
    }

    pub fn get_generator_summary(&self) -> &GarbledCircuit<gc_state::FullSummary> {
        &self.generated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    use std::sync::Arc;

    use crate::{
        commit::Opening,
        garble::{ActiveInputSet, Delta, Error, FullInputSet},
    };

    use mpc_circuits::{Circuit, Value, ADDER_64};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[fixture]
    fn circ() -> Arc<Circuit> {
        ADDER_64.clone()
    }

    #[rstest]
    fn test_zk_success(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let verifier = Verifier::new(circ.clone());
        let prover = Prover::new(circ.clone());

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let active_input_labels = full_input_set
            .iter()
            .map(|labels| labels.select(&Value::U64(1)).unwrap())
            .collect();
        let active_input_set = ActiveInputSet::new(active_input_labels).unwrap();

        let (gc, verifier) = verifier.garble(full_input_set).unwrap();

        let prover = prover.evaluate(gc.into(), active_input_set).unwrap();
        let (commitment, prover) = prover.commit();

        let (gc_opening, verifier) = verifier.store_commit(commitment).open();

        let prover = prover.validate(gc_opening.into()).unwrap();
        let (commit_opening, gc_output) = prover.reveal();

        let _ = verifier.verify(commit_opening, gc_output.into()).unwrap();
    }

    #[rstest]
    fn test_zk_fail_commit(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let verifier = Verifier::new(circ.clone());
        let prover = Prover::new(circ.clone());

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let active_input_labels = full_input_set
            .iter()
            .map(|labels| labels.select(&Value::U64(1)).unwrap())
            .collect();
        let active_input_set = ActiveInputSet::new(active_input_labels).unwrap();

        let (gc, verifier) = verifier.garble(full_input_set).unwrap();

        let prover = prover.evaluate(gc.into(), active_input_set).unwrap();
        let (_, prover) = prover.commit();

        // Send bogus commitment
        let malicious_commit = Opening::new(&[0u8; 32]).commit();

        let (gc_opening, verifier) = verifier.store_commit(malicious_commit).open();

        let prover = prover.validate(gc_opening.into()).unwrap();
        let (commit_opening, gc_output) = prover.reveal();

        let err = verifier
            .verify(commit_opening, gc_output.into())
            .unwrap_err();

        assert!(matches!(err, Error::CommitmentError(_)));
    }

    #[rstest]
    fn test_zk_fail_reveal(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let verifier = Verifier::new(circ.clone());
        let prover = Prover::new(circ.clone());

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let active_input_labels = full_input_set
            .iter()
            .map(|labels| labels.select(&Value::U64(1)).unwrap())
            .collect();
        let active_input_set = ActiveInputSet::new(active_input_labels).unwrap();

        let (gc, verifier) = verifier.garble(full_input_set).unwrap();

        let prover = prover.evaluate(gc.into(), active_input_set).unwrap();
        let (commitment, prover) = prover.commit();

        let (gc_opening, verifier) = verifier.store_commit(commitment).open();

        let prover = prover.validate(gc_opening.into()).unwrap();
        let (_, gc_output) = prover.reveal();

        // Send bogus commitment opening
        let malicious_commit_opening = Opening::new(&[0u8; 32]);

        let err = verifier
            .verify(malicious_commit_opening, gc_output.into())
            .unwrap_err();

        assert!(matches!(err, Error::CommitmentError(_)));
    }

    #[rstest]
    fn test_zk_open_bad_delta(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let verifier = Verifier::new(circ.clone());
        let prover = Prover::new(circ.clone());

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let active_input_labels = full_input_set
            .iter()
            .map(|labels| labels.select(&Value::U64(1)).unwrap())
            .collect();
        let active_input_set = ActiveInputSet::new(active_input_labels).unwrap();

        let (gc, verifier) = verifier.garble(full_input_set).unwrap();

        let prover = prover.evaluate(gc.into(), active_input_set).unwrap();
        let (commitment, prover) = prover.commit();

        let (mut gc_opening, _) = verifier.store_commit(commitment).open();

        // Replace with bogus delta
        gc_opening.delta = Delta::from([0; 16]);

        let err = prover.validate(gc_opening.into()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[rstest]
    fn test_zk_open_bad_decoding(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let verifier = Verifier::new(circ.clone());
        let prover = Prover::new(circ.clone());

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let active_input_labels = full_input_set
            .iter()
            .map(|labels| labels.select(&Value::U64(1)).unwrap())
            .collect();
        let active_input_set = ActiveInputSet::new(active_input_labels).unwrap();

        let (gc, verifier) = verifier.garble(full_input_set).unwrap();

        let prover = prover.evaluate(gc.into(), active_input_set).unwrap();
        let (commitment, prover) = prover.commit();

        let (mut gc_opening, _) = verifier.store_commit(commitment).open();

        // flip decoding bit
        gc_opening.input_decoding[0].decoding[0] = !gc_opening.input_decoding[0].decoding[0];

        let err = prover.validate(gc_opening.into()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }
}
