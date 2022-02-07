pub mod half_gate;

pub use half_gate::*;

use crate::circuit::Circuit;
use crate::errors::GeneratorError;
use crate::garble::circuit::GarbledCircuit;
use crate::garble::hash::WireLabelHasher;
use crate::prg::Prg;

pub trait GarbledCircuitGenerator {
    fn garble<P: Prg, H: WireLabelHasher>(
        &self,
        h: &H,
        prg: &mut P,
        circ: &Circuit,
    ) -> Result<GarbledCircuit, GeneratorError>;
}
