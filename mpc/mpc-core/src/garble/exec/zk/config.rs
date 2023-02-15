use std::sync::Arc;

use derive_builder::Builder;

use mpc_circuits::Circuit;

#[derive(Debug, Clone, Builder)]
pub struct ProverConfig {
    id: String,
    circ: Arc<Circuit>,
}

impl ProverConfig {
    /// Returns instance ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns circuit.
    pub fn circ(&self) -> Arc<Circuit> {
        self.circ.clone()
    }
}

#[derive(Debug, Clone, Builder)]
pub struct VerifierConfig {
    id: String,
    circ: Arc<Circuit>,
}

impl VerifierConfig {
    /// Returns instance ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns circuit.
    pub fn circ(&self) -> Arc<Circuit> {
        self.circ.clone()
    }
}
