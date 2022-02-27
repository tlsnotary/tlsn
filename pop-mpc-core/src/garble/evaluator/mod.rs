pub mod half_gate;

pub use half_gate::*;

use crate::circuit::Circuit;
use crate::errors::EvaluatorError;
use crate::garble::circuit::{GarbledCircuit, InputLabel};
use crate::Block;
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};

pub trait GarbledCircuitEvaluator {
    /// Evaluates a garbled circuit with the provided input labels
    fn eval<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        circ: &Circuit,
        gc: &GarbledCircuit,
        input_labels: Vec<InputLabel>,
    ) -> Result<Vec<bool>, EvaluatorError>;
}
