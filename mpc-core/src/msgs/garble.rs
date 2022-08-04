use crate::garble::{BinaryLabel, EncryptedGate};
use mpc_circuits::CircuitId;

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub id: CircuitId,
    pub input_labels: Vec<BinaryLabel>,
    pub encrypted_gates: Vec<EncryptedGate>,
    pub decoding: Option<Vec<bool>>,
}
