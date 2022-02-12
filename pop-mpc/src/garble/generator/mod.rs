pub mod half_gate;

pub use half_gate::*;

use crate::circuit::Circuit;
use crate::errors::GeneratorError;
use crate::garble::circuit::GarbledCircuit;
use crate::garble::hash::WireLabelHasher;
use rand::{CryptoRng, Rng};

pub trait GarbledCircuitGenerator {
    fn garble<R: Rng + CryptoRng, H: WireLabelHasher>(
        &self,
        h: &H,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<GarbledCircuit, GeneratorError>;
}
