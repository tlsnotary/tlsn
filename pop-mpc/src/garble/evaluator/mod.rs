pub mod half_gate;

pub use half_gate::*;

use crate::block::Block;
use crate::circuit::Circuit;
use crate::errors::EvaluatorError;
use crate::garble::circuit::GarbledCircuit;
use crate::garble::hash::WireLabelHasher;

pub trait GarbledCircuitEvaluator {
    fn eval<H: WireLabelHasher>(
        &self,
        h: &H,
        circ: &Circuit,
        gc: &GarbledCircuit,
        input_labels: Vec<Block>,
    ) -> Result<Vec<Block>, EvaluatorError>;
}
