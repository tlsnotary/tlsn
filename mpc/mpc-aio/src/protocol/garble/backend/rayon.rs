use std::sync::Arc;

use aes::{Aes128, NewBlockCipher};
use async_trait::async_trait;
use futures::channel::oneshot;

use mpc_circuits::Circuit;
use mpc_core::garble::{
    gc_state, ActiveInputLabels, CircuitOpening, Delta, FullInputLabels, GarbledCircuit,
};

use crate::protocol::garble::{Compressor, Evaluator, GCError, Generator, Validator};

/// Garbler backend using Rayon to garble and evaluate circuits asynchronously and in parallel
pub struct RayonBackend;

#[async_trait]
impl Generator for RayonBackend {
    async fn generate(
        &mut self,
        circ: Arc<Circuit>,
        delta: Delta,
        input_labels: &[FullInputLabels],
    ) -> Result<GarbledCircuit<gc_state::Full>, GCError> {
        let (sender, receiver) = oneshot::channel();
        let input_labels = input_labels.to_vec();
        rayon::spawn(move || {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let gc = GarbledCircuit::generate(&cipher, circ, delta, &input_labels)
                .map_err(GCError::from);
            _ = sender.send(gc);
        });
        receiver
            .await
            .map_err(|_| GCError::BackendError("channel error".to_string()))?
    }
}

#[async_trait]
impl Evaluator for RayonBackend {
    async fn evaluate(
        &mut self,
        circ: GarbledCircuit<gc_state::Partial>,
        input_labels: &[ActiveInputLabels],
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
        let (sender, receiver) = oneshot::channel();
        let input_labels = input_labels.to_vec();
        rayon::spawn(move || {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let ev = circ.evaluate(&cipher, &input_labels).map_err(GCError::from);
            _ = sender.send(ev);
        });
        receiver
            .await
            .map_err(|_| GCError::BackendError("channel error".to_string()))?
    }
}

#[async_trait]
impl Validator for RayonBackend {
    async fn validate_evaluated(
        &mut self,
        circ: GarbledCircuit<gc_state::Evaluated>,
        opening: CircuitOpening,
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            let circ = circ.validate(opening).map(|_| circ).map_err(GCError::from);
            _ = sender.send(circ);
        });
        receiver
            .await
            .map_err(|_| GCError::BackendError("channel error".to_string()))?
    }

    async fn validate_compressed(
        &mut self,
        circ: GarbledCircuit<gc_state::Compressed>,
        opening: CircuitOpening,
    ) -> Result<GarbledCircuit<gc_state::Compressed>, GCError> {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            let circ = circ.validate(opening).map(|_| circ).map_err(GCError::from);
            _ = sender.send(circ);
        });
        receiver
            .await
            .map_err(|_| GCError::BackendError("channel error".to_string()))?
    }
}

#[async_trait]
impl Compressor for RayonBackend {
    async fn compress(
        &mut self,
        circ: GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<GarbledCircuit<gc_state::Compressed>, GCError> {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            _ = sender.send(Ok(circ.compress()));
        });
        receiver
            .await
            .map_err(|_| GCError::BackendError("channel error".to_string()))?
    }
}

#[cfg(test)]
mod test {
    use mpc_circuits::ADDER_64;
    use mpc_core::garble::FullInputLabels;
    use rand::thread_rng;

    use super::*;

    #[tokio::test]
    async fn test_rayon_garbler() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (input_labels, delta) = FullInputLabels::generate_set(&mut thread_rng(), &circ, None);
        let gc = RayonBackend
            .generate(circ.clone(), delta, &input_labels)
            .await
            .unwrap();

        let input_labels = vec![
            input_labels[0].select(&0u64.into()).unwrap(),
            input_labels[1].select(&0u64.into()).unwrap(),
        ];

        let _ = RayonBackend
            .evaluate(gc.to_evaluator(&[], true, false).unwrap(), &input_labels)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_validator() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (full_input_labels, delta) =
            FullInputLabels::generate_set(&mut thread_rng(), &circ, None);
        let gc = RayonBackend
            .generate(circ.clone(), delta, &full_input_labels)
            .await
            .unwrap();
        let opening = gc.open();

        let input_labels = vec![
            full_input_labels[0].select(&0u64.into()).unwrap(),
            full_input_labels[1].select(&0u64.into()).unwrap(),
        ];

        let ev_gc = RayonBackend
            .evaluate(gc.to_evaluator(&[], true, false).unwrap(), &input_labels)
            .await
            .unwrap();

        let ev_gc = RayonBackend
            .validate_evaluated(ev_gc, opening.clone())
            .await
            .unwrap();

        let compressed_gc = RayonBackend.compress(ev_gc).await.unwrap();

        let _ = RayonBackend
            .validate_compressed(compressed_gc, opening)
            .await
            .unwrap();
    }
}
