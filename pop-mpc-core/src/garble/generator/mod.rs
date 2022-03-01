pub mod half_gate;

pub use half_gate::*;

use super::errors::GeneratorError;
use crate::circuit::Circuit;
use crate::garble::circuit::CompleteGarbledCircuit;
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use rand::{CryptoRng, Rng};

pub trait GarbledCircuitGenerator {
    /// Generates a garbled circuit
    fn garble<R: Rng + CryptoRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<CompleteGarbledCircuit, GeneratorError>;
}
