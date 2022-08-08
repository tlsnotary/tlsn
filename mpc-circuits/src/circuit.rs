use crate::{proto::Circuit as ProtoCircuit, Error};

use prost::Message;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

/// Group of circuit wires
#[derive(Debug, Clone)]
pub struct Group {
    name: String,
    desc: String,
    /// Wire ids
    wires: Vec<usize>,
}

impl Group {
    pub fn new(name: &str, desc: &str, wires: &[usize]) -> Self {
        let mut wires = wires.to_vec();
        // Ensure wire ids are always sorted
        wires.sort();
        Self {
            name: name.to_string(),
            desc: desc.to_string(),
            wires,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn desc(&self) -> &str {
        &self.desc
    }

    pub fn wires(&self) -> &[usize] {
        &self.wires
    }

    pub fn len(&self) -> usize {
        self.wires.len()
    }
}

/// Group of wires corresponding to a circuit input
#[derive(Debug, Clone)]
pub struct Input {
    /// Input id of circuit
    pub id: usize,
    group: Group,
}

impl Input {
    pub fn new(id: usize, group: Group) -> Self {
        Self { id, group }
    }

    pub fn to_value(&self, value: &[bool]) -> Result<InputValue, Error> {
        InputValue::new(self.clone(), value)
    }
}

impl AsRef<Group> for Input {
    fn as_ref(&self) -> &Group {
        &self.group
    }
}

/// Group of wires corresponding to a circuit output
#[derive(Debug, Clone)]
pub struct Output {
    /// Output id of circuit
    pub id: usize,
    group: Group,
}

impl Output {
    pub fn new(id: usize, group: Group) -> Self {
        Self { id, group }
    }

    pub fn to_value(&self, value: &[bool]) -> Result<OutputValue, Error> {
        OutputValue::new(self.clone(), value)
    }
}

impl AsRef<Group> for Output {
    fn as_ref(&self) -> &Group {
        &self.group
    }
}

/// Circuit input with corresponding wire values
#[derive(Debug, Clone)]
pub struct InputValue {
    input: Input,
    value: Vec<bool>,
}

impl InputValue {
    pub fn new(input: Input, value: &[bool]) -> Result<Self, Error> {
        if input.as_ref().len() != value.len() {
            return Err(Error::InvalidValue(input.as_ref().clone(), value.to_vec()));
        }
        Ok(Self {
            input,
            value: value.to_vec(),
        })
    }

    pub fn id(&self) -> usize {
        self.input.id
    }

    pub fn len(&self) -> usize {
        self.input.as_ref().len()
    }

    pub fn wires(&self) -> &[usize] {
        self.input.as_ref().wires()
    }
}

impl AsRef<[bool]> for InputValue {
    fn as_ref(&self) -> &[bool] {
        &self.value
    }
}

#[derive(Debug, Clone)]
pub struct OutputValue {
    output: Output,
    value: Vec<bool>,
}

impl AsRef<[bool]> for OutputValue {
    fn as_ref(&self) -> &[bool] {
        &self.value
    }
}

impl OutputValue {
    pub fn new(output: Output, value: &[bool]) -> Result<Self, Error> {
        if output.as_ref().len() != value.len() {
            return Err(Error::InvalidValue(output.as_ref().clone(), value.to_vec()));
        }
        Ok(Self {
            output,
            value: value.to_vec(),
        })
    }

    pub fn id(&self) -> usize {
        self.output.id
    }

    pub fn len(&self) -> usize {
        self.output.as_ref().len()
    }

    pub fn wires(&self) -> &[usize] {
        self.output.as_ref().wires()
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

impl Gate {
    pub(crate) fn to_bytes(&self) -> [u8; 16] {
        let (id, xref, yref, zref) = match *self {
            Gate::Xor {
                id,
                xref,
                yref,
                zref,
            } => (id as u32, xref as u32, yref as u32, zref as u32),
            Gate::And {
                id,
                xref,
                yref,
                zref,
            } => (id as u32, xref as u32, yref as u32, zref as u32),
            Gate::Inv { id, xref, zref } => (id as u32, xref as u32, u32::MAX, zref as u32),
        };
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&id.to_be_bytes());
        bytes[4..8].copy_from_slice(&xref.to_be_bytes());
        bytes[8..12].copy_from_slice(&yref.to_be_bytes());
        bytes[12..].copy_from_slice(&zref.to_be_bytes());
        bytes
    }
}

/// `CircuitId` is a unique identifier for a `Circuit` based on it's gate structure
#[derive(Debug, Clone, PartialEq)]
pub struct CircuitId(String);

impl CircuitId {
    pub(crate) fn new(gates: &[Gate]) -> Self {
        let mut hasher = Sha256::new();
        for gate in gates {
            hasher.update(&gate.to_bytes());
        }
        Self(hex::encode(hasher.finalize()))
    }
}

impl AsRef<String> for CircuitId {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl From<String> for CircuitId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

#[derive(Clone)]
pub struct Circuit {
    pub(crate) id: CircuitId,
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

    /// Groups of wires corresponding to circuit inputs
    pub(crate) inputs: Vec<Input>,
    /// Groups of wires corresponding to circuit outputs
    pub(crate) outputs: Vec<Output>,
    /// Circuit logic gates
    pub(crate) gates: Vec<Gate>,
}

impl std::fmt::Debug for Circuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Circuit")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("version", &self.version)
            .finish()
    }
}

impl Circuit {
    /// Loads a circuit from a byte-array in protobuf format
    pub fn load_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let circ = ProtoCircuit::decode(bytes)?;
        Circuit::try_from(circ).map_err(|_| Error::MappingError)
    }

    pub fn id(&self) -> &CircuitId {
        &self.id
    }

    /// Returns circuit name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns circuit version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns total number of wires in circuit
    pub fn len(&self) -> usize {
        self.wire_count
    }

    /// Returns group corresponding to input id
    pub fn input(&self, id: usize) -> Option<Input> {
        self.inputs.get(id).cloned()
    }

    /// Returns reference to all circuit inputs
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Returns number of inputs
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Returns the total number of input wires of the circuit
    pub fn input_len(&self) -> usize {
        self.inputs.iter().map(|input| input.as_ref().len()).sum()
    }

    /// Returns group corresponding to output id
    pub fn output(&self, id: usize) -> Option<Output> {
        self.outputs.get(id).cloned()
    }

    /// Returns reference to all circuit outputs
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Return number of outputs
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Returns the total number of input wires of the circuit
    pub fn output_len(&self) -> usize {
        self.outputs
            .iter()
            .map(|output| output.as_ref().len())
            .sum()
    }

    /// Returns circuit gates
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    /// Returns number of AND gates in circuit
    pub fn and_count(&self) -> usize {
        self.and_count
    }

    /// Returns number of XOR gates in circuit
    pub fn xor_count(&self) -> usize {
        self.xor_count
    }

    /// Validates circuit structure
    pub fn validate(&self) -> Result<(), Error> {
        todo!()
    }

    /// Evaluates the circuit in plaintext with the provided inputs
    pub fn evaluate(&self, inputs: &[InputValue]) -> Result<Vec<OutputValue>, Error> {
        let mut wires: Vec<Option<bool>> = vec![None; self.len()];
        for input in inputs {
            for (value, wire_id) in input.as_ref().iter().zip(input.wires()) {
                wires[*wire_id] = Some(*value);
            }
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

        let mut outputs: Vec<OutputValue> = Vec::with_capacity(self.output_count());
        for output in self.outputs.iter() {
            let mut value: Vec<bool> = Vec::with_capacity(output.as_ref().len());
            for id in output.as_ref().wires() {
                value.push(wires[*id].ok_or(Error::UninitializedWire(*id))?);
            }
            outputs.push(OutputValue::new(output.clone(), &value)?);
        }

        Ok(outputs)
    }
}
