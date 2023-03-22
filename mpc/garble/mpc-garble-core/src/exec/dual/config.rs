use std::sync::Arc;

use derive_builder::Builder;
use mpc_circuits::Circuit;

#[derive(Debug, Clone, Builder)]
pub struct DualExConfig {
    id: String,
    circ: Arc<Circuit>,
}

impl DualExConfig {
    /// Returns instance ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns circuit.
    pub fn circ(&self) -> Arc<Circuit> {
        self.circ.clone()
    }
}
