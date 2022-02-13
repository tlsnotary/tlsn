pub mod half_gate;

pub use half_gate::*;

use crate::circuit::Circuit;
use crate::errors::GeneratorError;
use crate::garble::circuit::GarbledCircuit;
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use rand::{CryptoRng, Rng};

pub trait GarbledCircuitGenerator {
    fn garble<R: Rng + CryptoRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<GarbledCircuit, GeneratorError>;
}
