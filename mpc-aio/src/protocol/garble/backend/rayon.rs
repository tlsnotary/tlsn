use std::sync::Arc;

use aes::{Aes128, NewBlockCipher};
use async_trait::async_trait;
use futures::channel::oneshot;

use mpc_circuits::Circuit;
use mpc_core::garble::{
    validate_compressed_circuit, validate_evaluated_circuit, Compressed, Delta, Evaluated, Full,
    GarbledCircuit, InputLabels, Partial, WireLabel, WireLabelPair,
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
        input_labels: &[InputLabels<WireLabelPair>],
    ) -> Result<GarbledCircuit<Full>, GCError> {
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
        circ: GarbledCircuit<Partial>,
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<GarbledCircuit<Evaluated>, GCError> {
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
        circ: GarbledCircuit<Evaluated>,
        delta: Delta,
        input_labels: &[InputLabels<WireLabelPair>],
    ) -> Result<GarbledCircuit<Evaluated>, GCError> {
        let (sender, receiver) = oneshot::channel();
        let input_labels = input_labels.to_vec();
        rayon::spawn(move || {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let circ = validate_evaluated_circuit(&cipher, delta, &input_labels, circ)
                .map_err(GCError::from);
            _ = sender.send(circ);
        });
        receiver
            .await
            .map_err(|_| GCError::BackendError("channel error".to_string()))?
    }

    async fn validate_compressed(
        &mut self,
        circ: GarbledCircuit<Compressed>,
        delta: Delta,
        input_labels: &[InputLabels<WireLabelPair>],
    ) -> Result<GarbledCircuit<Compressed>, GCError> {
        let (sender, receiver) = oneshot::channel();
        let input_labels = input_labels.to_vec();
        rayon::spawn(move || {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let circ = validate_compressed_circuit(&cipher, delta, &input_labels, circ)
                .map_err(GCError::from);
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
        circ: GarbledCircuit<Evaluated>,
    ) -> Result<GarbledCircuit<Compressed>, GCError> {
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
    use rand::thread_rng;

    use super::*;

    #[tokio::test]
    async fn test_rayon_garbler() {
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());
        let (input_labels, delta) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let gc = RayonBackend
            .generate(circ.clone(), delta, &input_labels)
            .await
            .unwrap();

        let input_labels = vec![
            input_labels[0]
                .select(&circ.input(0).unwrap().to_value(0u64).unwrap())
                .unwrap(),
            input_labels[1]
                .select(&circ.input(1).unwrap().to_value(0u64).unwrap())
                .unwrap(),
        ];

        let _ = RayonBackend
            .evaluate(gc.to_evaluator(&[], true, false), &input_labels)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_validator() {
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());
        let (full_input_labels, delta) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let gc = RayonBackend
            .generate(circ.clone(), delta, &full_input_labels)
            .await
            .unwrap();

        let input_labels = vec![
            full_input_labels[0]
                .select(&circ.input(0).unwrap().to_value(0u64).unwrap())
                .unwrap(),
            full_input_labels[1]
                .select(&circ.input(1).unwrap().to_value(0u64).unwrap())
                .unwrap(),
        ];

        let ev_gc = RayonBackend
            .evaluate(gc.to_evaluator(&[], true, false), &input_labels)
            .await
            .unwrap();

        let ev_gc = RayonBackend
            .validate_evaluated(ev_gc, delta, &full_input_labels)
            .await
            .unwrap();

        let compressed_gc = RayonBackend.compress(ev_gc).await.unwrap();

        let _ = RayonBackend
            .validate_compressed(compressed_gc, delta, &full_input_labels)
            .await
            .unwrap();
    }
}
