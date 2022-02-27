pub mod parse;

use crate::errors::CircuitEvalError;
use crate::gate::Gate;

pub use parse::*;

#[derive(Clone, Debug, PartialEq)]
pub struct Circuit {
    /// Number of gates in the circuit
    pub ngates: usize,
    /// Number of wires in the circuit
    pub nwires: usize,
    /// Number of inputs to the circuit
    pub ninputs: usize,
    /// Number of wires for each input to the circuit
    pub input_nwires: Vec<usize>,
    /// Total number of input wires
    pub ninput_wires: usize,
    /// Total number of output wires
    pub noutput_wires: usize,
    /// All gates in the circuit
    pub(crate) gates: Vec<Gate>,
    /// Total number of AND gates
    pub nand: usize,
    /// Total number of XOR gates
    pub nxor: usize,
}

impl Circuit {
    pub fn new(
        ngates: usize,
        nwires: usize,
        ninputs: usize,
        input_nwires: Vec<usize>,
        ninput_wires: usize,
        noutput_wires: usize,
    ) -> Self {
        Circuit {
            ngates,
            nwires,
            ninputs,
            input_nwires,
            ninput_wires,
            noutput_wires,
            gates: Vec::with_capacity(ngates),
            nand: 0,
            nxor: 0,
        }
    }

    /// Evaluates the circuit in plaintext with the provided inputs
    pub fn eval(&self, inputs: Vec<Vec<bool>>) -> Result<Vec<bool>, CircuitEvalError> {
        let mut wires: Vec<Option<bool>> = vec![None; self.nwires];
        let inputs = inputs.concat();
        for (i, input) in inputs.into_iter().enumerate() {
            wires[i] = Some(input);
        }

        for (i, gate) in self.gates.iter().enumerate() {
            let (zref, val) = match *gate {
                Gate::Xor {
                    xref, yref, zref, ..
                } => {
                    let x =
                        wires[xref].ok_or_else(|| CircuitEvalError::UninitializedValue(xref))?;
                    let y =
                        wires[yref].ok_or_else(|| CircuitEvalError::UninitializedValue(yref))?;
                    (zref, x ^ y)
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x =
                        wires[xref].ok_or_else(|| CircuitEvalError::UninitializedValue(xref))?;
                    let y =
                        wires[yref].ok_or_else(|| CircuitEvalError::UninitializedValue(yref))?;
                    (zref, x & y)
                }
                Gate::Inv { xref, zref, .. } => {
                    let x =
                        wires[xref].ok_or_else(|| CircuitEvalError::UninitializedValue(xref))?;
                    (zref, !x)
                }
            };
            wires[zref] = Some(val);
        }

        let outputs = wires[(self.nwires - self.noutput_wires)..]
            .to_vec()
            .iter()
            .map(|w| w.unwrap())
            .collect();
        Ok(outputs)
    }
}
