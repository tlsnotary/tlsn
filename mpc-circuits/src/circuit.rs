use crate::proto::Circuit as ProtoCircuit;
use crate::Error;
use prost::Message;

use std::convert::TryFrom;

/// Group of circuit wires
#[derive(Debug, Clone)]
pub enum Group {
    Input {
        name: String,
        desc: String,
        /// Wire ids
        wires: Vec<usize>,
    },
    Intermediate {
        name: String,
        desc: String,
        /// Wire ids
        wires: Vec<usize>,
    },
    Output {
        name: String,
        desc: String,
        /// Wire ids
        wires: Vec<usize>,
    },
}

impl Group {
    /// Returns name of the group
    pub fn name(&self) -> &str {
        match self {
            Group::Input { name, .. } => name,
            Group::Intermediate { name, .. } => name,
            Group::Output { name, .. } => name,
        }
    }

    /// Returns description of the group
    pub fn desc(&self) -> &str {
        match self {
            Group::Input { desc, .. } => desc,
            Group::Intermediate { desc, .. } => desc,
            Group::Output { desc, .. } => desc,
        }
    }

    /// Returns the number of wires in the group
    pub fn len(&self) -> usize {
        match self {
            Group::Input { wires, .. } => wires.len(),
            Group::Intermediate { wires, .. } => wires.len(),
            Group::Output { wires, .. } => wires.len(),
        }
    }
}

/// Logic gates of a circuit.
///
/// `id` represents the gate id.
///
/// `xref` and `yref` correspond to gate input wire ids.
///
/// `zref` corresponds to the gate output wire id.
#[derive(Debug, Clone, Copy)]
pub enum Gate {
    Xor {
        id: usize,
        xref: usize,
        yref: usize,
        zref: usize,
    },
    And {
        id: usize,
        xref: usize,
        yref: usize,
        zref: usize,
    },
    Inv {
        id: usize,
        xref: usize,
        zref: usize,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct CircuitDescription {
    /// Name of circuit
    pub(crate) name: String,
    /// Version of circuit
    pub(crate) version: String,

    /// Number of wires in the circuit
    pub(crate) wire_count: usize,
    /// Total number of AND gates
    pub(crate) and_count: usize,
    /// Total number of XOR gates
    pub(crate) xor_count: usize,

    pub(crate) inputs: Vec<Group>,
    pub(crate) outputs: Vec<Group>,
}

#[derive(Clone)]
pub struct Circuit {
    pub(crate) desc: CircuitDescription,
    pub(crate) gates: Vec<Gate>,
}

impl Circuit {
    /// Loads a circuit from a byte-array in protobuf format
    pub fn load_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let circ = ProtoCircuit::decode(bytes)?;
        Circuit::try_from(circ).map_err(|_| Error::MappingError)
    }

    /// Returns circuit name
    pub fn name(&self) -> &str {
        &self.desc.name
    }

    /// Returns circuit version
    pub fn version(&self) -> &str {
        &self.desc.version
    }

    /// Returns total number of wires in circuit
    pub fn len(&self) -> usize {
        self.desc.wire_count
    }

    /// Returns group corresponding to input id
    pub fn input(&self, id: usize) -> &Group {
        &self.desc.inputs[id]
    }

    /// Returns reference to all circuit inputs
    pub fn inputs(&self) -> &Vec<Group> {
        &self.desc.inputs
    }

    /// Returns number of inputs
    pub fn input_count(&self) -> usize {
        self.desc.inputs.len()
    }

    /// Returns the total number of input wires of the circuit
    pub fn input_len(&self) -> usize {
        self.desc.inputs.iter().map(|group| group.len()).sum()
    }

    /// Returns group corresponding to output id
    pub fn output(&self, id: usize) -> &Group {
        &self.desc.outputs[id]
    }

    /// Returns reference to all circuit outputs
    pub fn outputs(&self) -> &Vec<Group> {
        &self.desc.outputs
    }

    /// Return number of outputs
    pub fn output_count(&self) -> usize {
        self.desc.outputs.len()
    }

    /// Returns the total number of input wires of the circuit
    pub fn output_len(&self) -> usize {
        self.desc.outputs.iter().map(|group| group.len()).sum()
    }

    /// Returns circuit gates
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    /// Returns number of AND gates in circuit
    pub fn and_count(&self) -> usize {
        self.desc.and_count
    }

    /// Returns number of XOR gates in circuit
    pub fn xor_count(&self) -> usize {
        self.desc.xor_count
    }

    /// Validates circuit structure
    pub fn validate(&self) -> Result<(), Error> {
        todo!()
    }

    /// Evaluates the circuit in plaintext with the provided inputs
    pub fn evaluate(&self, inputs: &[bool]) -> Result<Vec<bool>, Error> {
        let mut wires: Vec<Option<bool>> = vec![None; self.len()];
        for (wire, input) in wires.iter_mut().zip(inputs) {
            *wire = Some(*input);
        }

        for gate in self.gates.iter() {
            let (zref, val) = match *gate {
                Gate::Xor {
                    xref, yref, zref, ..
                } => {
                    let x = wires[xref].ok_or(Error::UninitializedWire(xref))?;
                    let y = wires[yref].ok_or(Error::UninitializedWire(yref))?;
                    (zref, x ^ y)
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x = wires[xref].ok_or(Error::UninitializedWire(xref))?;
                    let y = wires[yref].ok_or(Error::UninitializedWire(yref))?;
                    (zref, x & y)
                }
                Gate::Inv { xref, zref, .. } => {
                    let x = wires[xref].ok_or(Error::UninitializedWire(xref))?;
                    (zref, !x)
                }
            };
            wires[zref] = Some(val);
        }

        let outputs = wires
            .drain(self.len() - self.output_len()..)
            .map(|wire| wire.unwrap())
            .collect();

        Ok(outputs)
    }
}
