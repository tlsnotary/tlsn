use crate::{proto::Circuit as ProtoCircuit, Error, Gate};
use prost::Message;

use std::convert::TryFrom;
use std::fs::read;

/// Circuit wire
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Wire {
    /// Wire id
    pub id: usize,
    /// Wire value
    pub value: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CircuitDescription {
    /// Name of circuit
    pub name: String,
    /// Version of circuit
    pub version: String,
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
    /// Total number of AND gates
    pub nand: usize,
    /// Total number of XOR gates
    pub nxor: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Circuit {
    pub desc: CircuitDescription,
    /// All gates in the circuit
    pub gates: Vec<Gate>,
}

impl Circuit {
    /// Loads a circuit stored in a file in protobuf format
    pub fn load(filename: &str) -> Result<Self, Error> {
        let file = read(filename)?;
        Self::load_bytes(file.as_slice())
    }

    /// Loads a circuit from a byte-array in protobuf format
    pub fn load_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let circ = ProtoCircuit::decode(bytes)?;
        Circuit::try_from(circ).map_err(|_| Error::MappingError)
    }

    /// Evaluates the circuit in plaintext with the provided inputs
    pub fn eval(&self, inputs: &[bool]) -> Result<Vec<bool>, Error> {
        let mut wires: Vec<Option<bool>> = vec![None; self.desc.nwires];
        for (wire, input) in wires.iter_mut().zip(inputs) {
            *wire = Some(*input);
        }

        for gate in self.gates.iter() {
            let (zref, val) = match *gate {
                Gate::Xor {
                    xref, yref, zref, ..
                } => {
                    let x = wires[xref].ok_or(Error::UninitializedValue(xref))?;
                    let y = wires[yref].ok_or(Error::UninitializedValue(yref))?;
                    (zref, x ^ y)
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x = wires[xref].ok_or(Error::UninitializedValue(xref))?;
                    let y = wires[yref].ok_or(Error::UninitializedValue(yref))?;
                    (zref, x & y)
                }
                Gate::Inv { xref, zref, .. } => {
                    let x = wires[xref].ok_or(Error::UninitializedValue(xref))?;
                    (zref, !x)
                }
            };
            wires[zref] = Some(val);
        }

        let outputs = wires
            .drain(self.desc.nwires - self.desc.noutput_wires..)
            .map(|wire| wire.unwrap())
            .collect();

        Ok(outputs)
    }
}
