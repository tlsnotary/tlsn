//! An implementation of malicious-secure zero-knowledge proofs using Garbled Circuits.
//!
//! This protocol allows a Prover to prove in zero-knowledge the output of a circuit to a Verifier
//! without leaking any information about their private inputs. The Verifier can also provide
//! private inputs which are revealed after the Prover commits to the output of the circuit.

mod prover;
mod verifier;

pub use prover::{state as prover_state, Prover};
pub use verifier::{state as verifier_state, Verifier};

use async_trait::async_trait;

use mpc_circuits::{Input, InputValue, OutputValue};
use mpc_core::garble::{ActiveEncodedInput, FullInputSet};

use crate::protocol::garble::GCError;

/// This trait faciliates proving the output of a circuit in
/// zero-knowledge.
#[async_trait]
pub trait Prove {
    /// Proves the output of a circuit to a Verifier.
    ///
    /// * `inputs` - The Prover's private inputs to the circuit.
    /// * `cached_labels` - Cached labels for the circuit's inputs.
    async fn prove(
        self,
        inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(), GCError>;
}

/// This trait faciliates verifying the output of a circuit in
/// zero-knowledge.
#[async_trait]
pub trait Verify {
    /// Verifies the authenticity of a circuit output evaluated by a Prover.
    ///
    /// **CAUTION**
    ///
    /// Calling this function will typically reveal all of the Verifier's private inputs to the Prover!
    /// Care must be taken to ensure that this is synchronized properly with any other uses of these inputs.
    ///
    /// * `gen_labels` - The labels used to garble the circuit.
    /// * `inputs` - The Verifier's private inputs to the circuit.
    /// * `ot_send_inputs` - The inputs which are to be sent to the Prover via OT.
    async fn verify(
        self,
        gen_labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
    ) -> Result<Vec<OutputValue>, GCError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    use std::sync::Arc;

    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use crate::protocol::{garble::backend::RayonBackend, ot::mock::mock_ot_pair};
    use mpc_circuits::{Circuit, Value, WireGroup, ADDER_64};
    use mpc_core::{garble::FullInputSet, msgs::garble::GarbleMessage};
    use utils_aio::duplex::DuplexChannel;

    #[fixture]
    fn circ() -> Arc<Circuit> {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    #[rstest]
    #[tokio::test]
    async fn test_zk_both_inputs(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let (prover_channel, verifier_channel) = DuplexChannel::<GarbleMessage>::new();
        let (ot_sender, ot_receiver) = mock_ot_pair();

        let verifier = Verifier::new(
            circ.clone(),
            Box::new(verifier_channel),
            RayonBackend,
            Some(ot_sender),
        );

        let prover = Prover::new(
            circ.clone(),
            Box::new(prover_channel),
            RayonBackend,
            Some(ot_receiver),
        );

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let prover_fut = {
            let circ = circ.clone();
            async move {
                prover
                    .setup_inputs(vec![circ.input(0).unwrap().to_value(1u64).unwrap()], vec![])
                    .await
                    .unwrap()
                    .evaluate()
                    .await
                    .unwrap()
                    .prove()
                    .await
                    .unwrap();
            }
        };

        let verifier_fut = async move {
            verifier
                .setup_inputs(
                    full_input_set,
                    vec![circ.input(1).unwrap().to_value(1u64).unwrap()],
                    vec![circ.input(0).unwrap()],
                )
                .await
                .unwrap()
                .garble()
                .await
                .unwrap()
                .verify()
                .await
                .unwrap()
        };

        let (_, output) = futures::join!(prover_fut, verifier_fut);

        assert_eq!(output[0].value(), &Value::U64(2));
    }

    #[rstest]
    #[tokio::test]
    async fn test_zk_prover_inputs(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let (prover_channel, verifier_channel) = DuplexChannel::<GarbleMessage>::new();
        let (ot_sender, ot_receiver) = mock_ot_pair();

        let verifier = Verifier::new(
            circ.clone(),
            Box::new(verifier_channel),
            RayonBackend,
            Some(ot_sender),
        );

        let prover = Prover::new(
            circ.clone(),
            Box::new(prover_channel),
            RayonBackend,
            Some(ot_receiver),
        );

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let prover_fut = {
            let circ = circ.clone();
            async move {
                prover
                    .setup_inputs(
                        vec![
                            circ.input(0).unwrap().to_value(1u64).unwrap(),
                            circ.input(1).unwrap().to_value(1u64).unwrap(),
                        ],
                        vec![],
                    )
                    .await
                    .unwrap()
                    .evaluate()
                    .await
                    .unwrap()
                    .prove()
                    .await
                    .unwrap();
            }
        };

        let verifier_fut = async move {
            verifier
                .setup_inputs(
                    full_input_set,
                    vec![],
                    vec![circ.input(0).unwrap(), circ.input(1).unwrap()],
                )
                .await
                .unwrap()
                .garble()
                .await
                .unwrap()
                .verify()
                .await
                .unwrap()
        };

        let (_, output) = futures::join!(prover_fut, verifier_fut);

        assert_eq!(output[0].value(), &Value::U64(2));
    }
}
