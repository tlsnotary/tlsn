pub mod half_gate;

pub use half_gate::*;

use crate::block::Block;
use crate::circuit::Circuit;
use crate::errors::EvaluatorError;
use crate::garble::circuit::GarbledCircuit;
use cipher::{BlockCipher, BlockEncrypt, consts::U16, generic_array::GenericArray};

pub trait GarbledCircuitEvaluator {
    fn eval<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        circ: &Circuit,
        gc: &GarbledCircuit,
        input_labels: Vec<Block>,
    ) -> Result<Vec<Block>, EvaluatorError>;
}
