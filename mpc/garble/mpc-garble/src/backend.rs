use crate::{Compressor, Evaluator, GCError, Generator, Validator};
use aes::{Aes128, NewBlockCipher};
use async_trait::async_trait;
use mpc_circuits::Circuit;
use mpc_garble_core::{gc_state, ActiveInputSet, CircuitOpening, FullInputSet, GarbledCircuit};
use std::sync::Arc;
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

/// Garbler backend to garble and evaluate circuits asynchronously and in parallel
#[derive(Clone)]
pub struct GarbleBackend;

#[async_trait]
impl Generator for GarbleBackend {
    async fn generate(
        &mut self,
        circ: Arc<Circuit>,
        input_labels: FullInputSet,
    ) -> Result<GarbledCircuit<gc_state::Full>, GCError> {
        Backend::spawn(move || {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            GarbledCircuit::generate(&cipher, circ, input_labels).map_err(GCError::from)
        })
        .await
    }
}

#[async_trait]
impl Evaluator for GarbleBackend {
    async fn evaluate(
        &mut self,
        circ: GarbledCircuit<gc_state::Partial>,
        input_labels: ActiveInputSet,
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
        Backend::spawn(move || {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            circ.evaluate(&cipher, input_labels).map_err(GCError::from)
        })
        .await
    }
}

#[async_trait]
impl Validator for GarbleBackend {
    async fn validate_evaluated(
        &mut self,
        circ: GarbledCircuit<gc_state::Evaluated>,
        opening: CircuitOpening,
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
        Backend::spawn(move || circ.validate(opening).map(|_| circ).map_err(GCError::from)).await
    }

    async fn validate_compressed(
        &mut self,
        circ: GarbledCircuit<gc_state::Compressed>,
        opening: CircuitOpening,
    ) -> Result<GarbledCircuit<gc_state::Compressed>, GCError> {
        Backend::spawn(move || circ.validate(opening).map(|_| circ).map_err(GCError::from)).await
    }
}

#[async_trait]
impl Compressor for GarbleBackend {
    async fn compress(
        &mut self,
        circ: GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<GarbledCircuit<gc_state::Compressed>, GCError> {
        Backend::spawn(move || Ok(circ.into_compressed())).await
    }
}

#[cfg(test)]
mod test {
    use mpc_circuits::ADDER_64;
    use rand::thread_rng;

    use super::*;

    #[tokio::test]
    async fn test_rayon_garbler() {
        let circ = ADDER_64.clone();
        let input_labels = FullInputSet::generate(&mut thread_rng(), &circ, None);
        let gc = GarbleBackend
            .generate(circ.clone(), input_labels.clone())
            .await
            .unwrap();

        let input_labels = ActiveInputSet::new(vec![
            input_labels[0].select(&0u64.into()).unwrap(),
            input_labels[1].select(&0u64.into()).unwrap(),
        ])
        .unwrap();

        let _ = GarbleBackend
            .evaluate(gc.get_partial(true, false).unwrap(), input_labels)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_validator() {
        let circ = ADDER_64.clone();
        let input_labels = FullInputSet::generate(&mut thread_rng(), &circ, None);

        let gc = GarbleBackend
            .generate(circ.clone(), input_labels.clone())
            .await
            .unwrap();
        let opening = gc.open();

        let input_labels = ActiveInputSet::new(vec![
            input_labels[0].select(&0u64.into()).unwrap(),
            input_labels[1].select(&0u64.into()).unwrap(),
        ])
        .unwrap();

        let ev_gc = GarbleBackend
            .evaluate(gc.get_partial(true, false).unwrap(), input_labels)
            .await
            .unwrap();

        let ev_gc = GarbleBackend
            .validate_evaluated(ev_gc, opening.clone())
            .await
            .unwrap();

        let compressed_gc = GarbleBackend.compress(ev_gc).await.unwrap();

        let _ = GarbleBackend
            .validate_compressed(compressed_gc, opening)
            .await
            .unwrap();
    }
}
