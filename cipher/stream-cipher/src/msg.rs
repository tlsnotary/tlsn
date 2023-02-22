#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use mpc_core::garble::Label;

#[derive(Debug)]
pub enum StreamCipherMessage {
    PlaintextLabels(PlaintextLabels),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlaintextLabels {
    pub labels: Vec<Label>,
}
