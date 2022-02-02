pub mod half_gate;

use crate::errors::GarbleGeneratorError;

pub trait GarbledCircuitGenerator {
    fn encode_wire_labels(&mut self) -> Result<(), GarbleGeneratorError>;
}
