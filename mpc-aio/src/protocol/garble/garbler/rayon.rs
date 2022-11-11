use std::sync::Arc;

use aes::{Aes128, NewBlockCipher};
use async_trait::async_trait;
use futures::channel::oneshot;

use mpc_circuits::Circuit;
use mpc_core::garble::{
    Delta, Evaluated, Full, GarbledCircuit, InputLabels, Partial, WireLabel, WireLabelPair,
};

use crate::protocol::garble::{Evaluator, GCError, Generator};

/// Garbler backend using Rayon to garble and evaluate circuits asynchronously and in parallel
pub struct RayonGarbler;

#[async_trait]
impl Generator for RayonGarbler {
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
            .map_err(|_| GCError::GarblerError("channel error".to_string()))?
    }
}

#[async_trait]
impl Evaluator for RayonGarbler {
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
            .map_err(|_| GCError::GarblerError("channel error".to_string()))?
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
        let gc = RayonGarbler
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

        let _ = RayonGarbler
            .evaluate(gc.to_evaluator(&[], true, false), &input_labels)
            .await
            .unwrap();
    }
}
