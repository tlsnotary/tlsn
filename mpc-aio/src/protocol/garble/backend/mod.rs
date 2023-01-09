mod rayon;

pub use self::rayon::RayonBackend;

#[cfg(feature = "mock")]
mod mock {
    use std::sync::Arc;

    use aes::{Aes128, NewBlockCipher};
    use async_trait::async_trait;

    use crate::protocol::garble::{Evaluator, GCError, Generator};
    use mpc_circuits::Circuit;
    use mpc_core::garble::{gc_state, ActiveInputLabels, Delta, FullInputLabels, GarbledCircuit};

    pub struct MockBackend;

    #[async_trait]
    impl Generator for MockBackend {
        async fn generate(
            &mut self,
            circ: Arc<Circuit>,
            delta: Delta,
            input_labels: &[FullInputLabels],
        ) -> Result<GarbledCircuit<gc_state::Full>, GCError> {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            Ok(GarbledCircuit::generate(
                &cipher,
                circ,
                delta,
                input_labels,
            )?)
        }
    }

    #[async_trait]
    impl Evaluator for MockBackend {
        async fn evaluate(
            &mut self,
            circ: GarbledCircuit<gc_state::Partial>,
            input_labels: &[ActiveInputLabels],
        ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            Ok(circ.evaluate(&cipher, input_labels)?)
        }
    }
}

#[cfg(feature = "mock")]
pub use mock::MockBackend;
