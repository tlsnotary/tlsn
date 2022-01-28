pub mod parse;

use crate::element::GateOps;
use crate::errors::CircuitEvalError;
use crate::gate::Gate;

#[derive(Clone, Debug, PartialEq)]
pub struct Circuit {
    /// Number of gates in the circuit
    pub(crate) ngates: usize,
    /// Number of wires in the circuit
    pub(crate) nwires: usize,
    /// Number of inputs to the circuit
    pub(crate) ninputs: usize,
    /// Number of wires for each input to the circuit
    pub(crate) input_nwires: Vec<usize>,
    /// Total number of input wires
    pub(crate) ninput_wires: usize,
    /// Total number of output wires
    pub(crate) noutput_wires: usize,
    /// All gates in the circuit
    pub(crate) gates: Vec<Gate>,
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
        }
    }

    pub fn eval<E: GateOps>(&self, inputs: Vec<Vec<E>>) -> Result<Vec<E>, CircuitEvalError> {
        let mut wires: Vec<Option<E>> = vec![None; self.nwires];
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
                    let val = x.xor(&y)?;
                    (zref, val)
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x =
                        wires[xref].ok_or_else(|| CircuitEvalError::UninitializedValue(xref))?;
                    let y =
                        wires[yref].ok_or_else(|| CircuitEvalError::UninitializedValue(yref))?;
                    let val = x.and(&y)?;
                    (zref, val)
                }
                Gate::Inv { xref, zref, .. } => {
                    let x =
                        wires[xref].ok_or_else(|| CircuitEvalError::UninitializedValue(xref))?;
                    let val = x.inv()?;
                    (zref, val)
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
