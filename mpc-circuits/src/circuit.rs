use crate::{
    error::ValueError, proto::Circuit as ProtoCircuit, utils::topological_sort, CircuitError,
    Value, ValueType,
};

use prost::Message;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, convert::TryFrom};

/// Group of circuit wires
#[derive(Debug, Clone)]
pub struct Group {
    name: String,
    desc: String,
    value_type: ValueType,
    /// Wire ids
    pub(crate) wires: Vec<usize>,
}

impl Group {
    pub fn new(name: &str, desc: &str, value_type: ValueType, wires: &[usize]) -> Self {
        let mut wires = wires.to_vec();
        // Ensure wire ids are always sorted
        wires.sort();
        Self {
            name: name.to_string(),
            desc: desc.to_string(),
            value_type,
            wires,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn desc(&self) -> &str {
        &self.desc
    }

    pub fn value_type(&self) -> ValueType {
        self.value_type
    }

    pub fn wires(&self) -> &[usize] {
        &self.wires
    }

    pub fn len(&self) -> usize {
        self.wires.len()
    }
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        self.wires == other.wires
    }
}

/// Group of wires corresponding to a circuit input
#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    /// Input id of circuit
    pub id: usize,
    pub(crate) group: Group,
}

impl Input {
    /// Creates a new circuit input
    pub fn new(id: usize, group: Group) -> Self {
        Self { id, group }
    }

    /// Returns value type
    pub fn value_type(&self) -> ValueType {
        self.group.value_type()
    }

    /// Parses bits to [`InputValue`]
    pub fn parse_bits(&self, bits: Vec<bool>) -> Result<InputValue, CircuitError> {
        InputValue::new(self.clone(), Value::new(self.group.value_type(), bits)?)
    }

    /// Converts input to [`InputValue`]
    pub fn to_value(&self, value: impl Into<Value>) -> Result<InputValue, CircuitError> {
        InputValue::new(self.clone(), value.into())
    }
}

impl AsRef<Group> for Input {
    fn as_ref(&self) -> &Group {
        &self.group
    }
}

/// Group of wires corresponding to one circuit output (a circuit may have
/// multiple outputs)
#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    /// Output id of circuit
    pub id: usize,
    pub(crate) group: Group,
}

impl Output {
    /// Creates a new circuit output
    pub fn new(id: usize, group: Group) -> Self {
        Self { id, group }
    }

    /// Returns value type
    pub fn value_type(&self) -> ValueType {
        self.group.value_type()
    }

    /// Parses bits to [`OutputValue`]
    pub fn parse_bits(&self, bits: Vec<bool>) -> Result<OutputValue, CircuitError> {
        OutputValue::new(self.clone(), Value::new(self.group.value_type(), bits)?)
    }

    /// Converts output to [`OutputValue`]
    pub fn to_value(&self, value: impl Into<Value>) -> Result<OutputValue, CircuitError> {
        OutputValue::new(self.clone(), value.into())
    }
}

impl AsRef<Group> for Output {
    fn as_ref(&self) -> &Group {
        &self.group
    }
}

/// Circuit input with corresponding wire values
#[derive(Debug, Clone, PartialEq)]
pub struct InputValue {
    input: Input,
    value: Value,
}

impl InputValue {
    /// Creates new input value
    pub fn new(input: Input, value: Value) -> Result<Self, CircuitError> {
        if input.group.value_type() != value.value_type() {
            return Err(CircuitError::ValueError(ValueError::InvalidType(
                input.group,
                value.value_type(),
            )));
        }
        Ok(Self { input, value })
    }

    /// Returns input id
    pub fn id(&self) -> usize {
        self.input.id
    }

    /// Returns value
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Returns input value type
    pub fn value_type(&self) -> ValueType {
        self.input.value_type()
    }

    /// Returns [`Input`] corresponding to this value
    pub fn input(&self) -> &Input {
        &self.input
    }

    /// Returns number of wires corresponding to this input
    pub fn len(&self) -> usize {
        self.input.as_ref().len()
    }

    /// Returns reference to input wires
    pub fn wires(&self) -> &[usize] {
        self.input.as_ref().wires()
    }

    /// Returns wire values
    pub fn wire_values(&self) -> Vec<bool> {
        self.value.to_bits()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputValue {
    output: Output,
    value: Value,
}

impl OutputValue {
    /// Creates new output value
    pub fn new(output: Output, value: Value) -> Result<Self, CircuitError> {
        if output.group.value_type() != value.value_type() {
            return Err(CircuitError::ValueError(ValueError::InvalidType(
                output.group,
                value.value_type(),
            )));
        }
        Ok(Self { output, value })
    }

    /// Returns output id
    pub fn id(&self) -> usize {
        self.output.id
    }

    /// Returns value
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Returns output value type
    pub fn value_type(&self) -> ValueType {
        self.output.value_type()
    }

    /// Returns [`Output`] corresponding to this value
    pub fn input(&self) -> &Output {
        &self.output
    }

    /// Returns number of wires corresponding to this output
    pub fn len(&self) -> usize {
        self.output.as_ref().len()
    }

    /// Returns reference to output wires
    pub fn wires(&self) -> &[usize] {
        self.output.as_ref().wires()
    }

    /// Returns wire values
    pub fn wire_values(&self) -> Vec<bool> {
        self.value.to_bits()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum GateType {
    Xor,
    And,
    Inv,
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
    /// Returns gate id
    pub fn id(&self) -> usize {
        match self {
            Gate::Xor { id, .. } => *id,
            Gate::And { id, .. } => *id,
            Gate::Inv { id, .. } => *id,
        }
    }

    /// Returns gate xref
    pub fn xref(&self) -> usize {
        match self {
            Gate::Xor { xref, .. } => *xref,
            Gate::And { xref, .. } => *xref,
            Gate::Inv { xref, .. } => *xref,
        }
    }

    /// Sets new wire id for xref
    pub(crate) fn set_xref(&mut self, id: usize) {
        match self {
            Gate::Xor { xref, .. } => *xref = id,
            Gate::And { xref, .. } => *xref = id,
            Gate::Inv { xref, .. } => *xref = id,
        }
    }

    /// Returns gate yref
    pub fn yref(&self) -> Option<usize> {
        match self {
            Gate::Xor { yref, .. } => Some(*yref),
            Gate::And { yref, .. } => Some(*yref),
            Gate::Inv { .. } => None,
        }
    }

    /// Sets new wire id for yref
    pub(crate) fn set_yref(&mut self, id: usize) {
        match self {
            Gate::Xor { yref, .. } => *yref = id,
            Gate::And { yref, .. } => *yref = id,
            Gate::Inv { .. } => panic!("tried to set yref of INV gate"),
        }
    }

    /// Returns gate zref
    pub fn zref(&self) -> usize {
        match self {
            Gate::Xor { zref, .. } => *zref,
            Gate::And { zref, .. } => *zref,
            Gate::Inv { zref, .. } => *zref,
        }
    }

    /// Sets new wire id for zref
    pub(crate) fn set_zref(&mut self, id: usize) {
        match self {
            Gate::Xor { zref, .. } => *zref = id,
            Gate::And { zref, .. } => *zref = id,
            Gate::Inv { zref, .. } => *zref = id,
        }
    }

    /// Returns whether gate is XOR
    pub fn is_xor(&self) -> bool {
        matches!(self, Gate::Xor { .. })
    }

    /// Returns whether gate is AND
    pub fn is_and(&self) -> bool {
        matches!(self, Gate::And { .. })
    }

    /// Returns whether gate is INV
    pub fn is_inv(&self) -> bool {
        matches!(self, Gate::Inv { .. })
    }

    /// Returns gate type
    pub fn gate_type(&self) -> GateType {
        match self {
            Gate::Xor { .. } => GateType::Xor,
            Gate::And { .. } => GateType::And,
            Gate::Inv { .. } => GateType::Inv,
        }
    }

    fn validate(&self) -> Result<(), CircuitError> {
        match *self {
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                if xref == zref || yref == zref {
                    return Err(CircuitError::InvalidCircuit(format!(
                        "invalid gate: {:?}",
                        self
                    )));
                }
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                if xref == zref || yref == zref {
                    return Err(CircuitError::InvalidCircuit(format!(
                        "invalid gate: {:?}",
                        self
                    )));
                }
            }
            Gate::Inv { xref, zref, .. } => {
                if xref == zref {
                    return Err(CircuitError::InvalidCircuit(format!(
                        "invalid gate: {:?}",
                        self
                    )));
                }
            }
        }
        Ok(())
    }

    fn wires(&self) -> Vec<usize> {
        match *self {
            Gate::Xor {
                xref, yref, zref, ..
            } => vec![xref, yref, zref],
            Gate::And {
                xref, yref, zref, ..
            } => vec![xref, yref, zref],
            Gate::Inv { xref, zref, .. } => vec![xref, zref],
        }
    }

    /// Serializes gate wire references to byte array
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

/// `CircuitId` is a unique identifier for a `Circuit` based on its gate structure
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

/// Binary Circuit
///
/// Circuits Wire IDs are in ascending order, organized in the following manner:
/// 1. Input wires
/// 2. Gate wires
/// 3. Output wires
///
/// Invariants of circuit structure:
/// 1. A circuit MUST be acyclic, ie a gate output wire MUST NOT be connected to one of its inputs directly or indirectly
/// 2. Input wires MUST be connected to gate inputs
/// 3. Output wires MUST be connected to gate outputs
/// 4. Gates MUST be sorted topologically
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

    /// All input ids in ascending order
    pub(crate) input_ids: Vec<usize>,
    /// All output ids in ascending order
    pub(crate) output_ids: Vec<usize>,

    /// Groups of wires corresponding to circuit inputs
    pub(crate) inputs: Vec<Input>,
    /// Constant inputs
    pub(crate) const_inputs: Vec<Input>,
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

struct CircuitInfo {
    wire_count: usize,
    and_count: usize,
    xor_count: usize,
}

impl Circuit {
    /// Creates a new circuit
    ///
    /// This function may return an error if one of the validation checks fails.
    ///
    /// Circuit wire ids are expected to be sorted and arranged in the following order:
    ///  1. Input wires
    ///  2. Intermediate gate wires
    ///  3. Output wires
    ///
    /// All input and output wires must belong to a [`Group`].
    ///
    /// [`Gate`] wires can not be connected to themselves, ie the [`Circuit`] must be acyclic.
    pub fn new(
        name: &str,
        version: &str,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        gates: Vec<Gate>,
    ) -> Result<Self, CircuitError> {
        let (inputs, input_wires) = Self::validate_inputs(inputs)?;
        let (outputs, output_wires) = Self::validate_outputs(outputs)?;
        let (gates, info) = Self::validate_gates(gates, &input_wires, &output_wires)?;
        let const_inputs = inputs
            .iter()
            .filter(|input| input.value_type().is_constant())
            .cloned()
            .collect();

        Ok(Self {
            id: CircuitId::new(&gates),
            name: name.to_string(),
            version: version.to_string(),
            wire_count: info.wire_count,
            and_count: info.and_count,
            xor_count: info.xor_count,
            input_ids: inputs.iter().map(|input| input.id).collect(),
            output_ids: outputs.iter().map(|output| output.id).collect(),
            inputs,
            const_inputs,
            outputs,
            gates: topological_sort(gates),
        })
    }

    /// Creates new circuit without performing any checks on circuit structure
    pub(crate) fn new_unchecked(
        name: &str,
        version: &str,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        gates: Vec<Gate>,
    ) -> Self {
        let info = Self::compute_stats(&gates);
        let const_inputs = inputs
            .iter()
            .filter(|input| input.value_type().is_constant())
            .cloned()
            .collect();
        Self {
            id: CircuitId::new(&gates),
            name: name.to_string(),
            version: version.to_string(),
            wire_count: info.wire_count,
            and_count: info.and_count,
            xor_count: info.xor_count,
            input_ids: inputs.iter().map(|input| input.id).collect(),
            output_ids: outputs.iter().map(|output| output.id).collect(),
            inputs,
            const_inputs,
            outputs,
            gates,
        }
    }

    fn validate_inputs(mut inputs: Vec<Input>) -> Result<(Vec<Input>, Vec<usize>), CircuitError> {
        // Sort inputs by input id
        inputs.sort_by_key(|input| input.id);

        let mut input_ids: Vec<usize> = inputs.iter().map(|input| input.id).collect();
        let input_count = input_ids.len();
        input_ids.dedup();

        // Make sure duplicates inputs are not present
        if input_count != input_ids.len() {
            return Err(CircuitError::InvalidCircuit(
                "Duplicate input ids".to_string(),
            ));
        }

        // Gather up and sort input wire ids
        let mut input_wire_ids: Vec<usize> = inputs
            .iter()
            .map(|input| input.as_ref().wires())
            .flatten()
            .cloned()
            .collect();
        input_wire_ids.sort();

        let input_wire_count = input_wire_ids.len();
        input_wire_ids.dedup();

        // Make sure input wires only belong to 1 input
        if input_wire_count != input_wire_ids.len() {
            return Err(CircuitError::InvalidCircuit(
                "Duplicate input wire ids".to_string(),
            ));
        }
        Ok((inputs, input_wire_ids))
    }

    fn validate_outputs(
        mut outputs: Vec<Output>,
    ) -> Result<(Vec<Output>, Vec<usize>), CircuitError> {
        // Sort outputs by output id
        outputs.sort_by_key(|output| output.id);

        let mut output_ids: Vec<usize> = outputs.iter().map(|output| output.id).collect();
        let output_count = output_ids.len();
        output_ids.dedup();

        // Make sure duplicate outputs are not present
        if output_count != output_ids.len() {
            return Err(CircuitError::InvalidCircuit(
                "Duplicate output ids".to_string(),
            ));
        }

        // Gather up and sort output wire ids
        let mut output_wire_ids: Vec<usize> = outputs
            .iter()
            .map(|output| output.as_ref().wires())
            .flatten()
            .cloned()
            .collect();
        output_wire_ids.sort();

        let output_wire_count = output_wire_ids.len();
        output_wire_ids.dedup();

        // Make sure output wires only belong to 1 output
        if output_wire_count != output_wire_ids.len() {
            return Err(CircuitError::InvalidCircuit(
                "Duplicate output wire ids".to_string(),
            ));
        }
        Ok((outputs, output_wire_ids))
    }

    fn compute_stats(gates: &[Gate]) -> CircuitInfo {
        let mut and_count = 0;
        let mut xor_count = 0;
        let mut wires = HashSet::with_capacity(gates.len() * 3);
        for gate in gates {
            wires.extend(gate.wires());
            if gate.is_and() {
                and_count += 1;
            } else if gate.is_xor() {
                xor_count += 1;
            }
        }
        CircuitInfo {
            wire_count: wires.len(),
            and_count,
            xor_count,
        }
    }

    fn validate_gates(
        gates: Vec<Gate>,
        input_wires: &[usize],
        output_wires: &[usize],
    ) -> Result<(Vec<Gate>, CircuitInfo), CircuitError> {
        if gates.len() == 0 {
            return Err(CircuitError::InvalidCircuit(
                "Circuits must have at least 1 gate".to_string(),
            ));
        }

        let mut and_count = 0;
        let mut xor_count = 0;
        let mut gate_output_wire_ids: Vec<usize> = Vec::with_capacity(gates.len());
        let mut gate_input_wire_ids: HashSet<usize> = HashSet::with_capacity(gates.len());
        let mut wire_ids: Vec<usize> = Vec::with_capacity(gates.len() * 3);

        for gate in gates.iter() {
            gate.validate()?;
            wire_ids.extend(gate.wires());
            gate_output_wire_ids.push(gate.zref());
            gate_input_wire_ids.insert(gate.xref());
            if gate.is_and() {
                and_count += 1;
                gate_input_wire_ids.insert(gate.yref().unwrap());
            } else if gate.is_xor() {
                xor_count += 1;
                gate_input_wire_ids.insert(gate.yref().unwrap());
            }
        }

        wire_ids.sort();
        wire_ids.dedup();
        let wire_count = wire_ids.len();

        // Check that wire ids start at 0 and are contiguous
        if wire_ids[0] != 0 || !(1..wire_count).all(|i| (wire_ids[i] - wire_ids[i - 1]) == 1) {
            return Err(CircuitError::InvalidCircuit(
                "Wire ids must start at 0 and be contiguous".to_string(),
            ));
        }

        gate_output_wire_ids.sort();
        let duplicate_output_wire_ids = {
            let mut dups: HashSet<usize> = HashSet::with_capacity(gate_output_wire_ids.len());
            let mut set: HashSet<usize> = HashSet::with_capacity(gate_output_wire_ids.len());
            for id in gate_output_wire_ids.iter() {
                if let Some(_) = set.get(id) {
                    dups.insert(*id);
                } else {
                    set.insert(*id);
                }
            }
            dups
        };

        // Check that all gate output wires are unique
        if duplicate_output_wire_ids.len() > 0 {
            return Err(CircuitError::InvalidCircuit(format!(
                "Duplicate gate output wire ids: {:?}",
                duplicate_output_wire_ids
            )));
        }

        let wire_ids: HashSet<usize> = HashSet::from_iter(wire_ids);
        let input_wire_ids: HashSet<usize> = HashSet::from_iter(input_wires.iter().copied());
        let output_wire_ids: HashSet<usize> = HashSet::from_iter(output_wires.iter().copied());
        let gate_output_wire_ids: HashSet<usize> = HashSet::from_iter(gate_output_wire_ids);

        // Check that all gate input wires in the first layer are assigned to an Input
        let expected_input_ids = wire_ids
            .difference(&gate_output_wire_ids)
            .cloned()
            .collect::<HashSet<usize>>();
        if expected_input_ids != input_wire_ids {
            let mut diff = expected_input_ids
                .difference(&input_wire_ids)
                .copied()
                .collect::<Vec<usize>>();
            diff.sort();
            return Err(CircuitError::InvalidCircuit(format!(
                "All input wires must be mapped to gate inputs: {:?}",
                diff
            )));
        }

        // Check that all Output wires are mapped to a gate output
        if !gate_output_wire_ids.is_superset(&output_wire_ids) {
            let mut diff = output_wire_ids
                .difference(&gate_output_wire_ids)
                .copied()
                .collect::<Vec<usize>>();
            diff.sort();
            return Err(CircuitError::InvalidCircuit(format!(
                "All output wires must be mapped to gate outputs: {:?}",
                diff
            )));
        }

        Ok((
            gates,
            CircuitInfo {
                wire_count,
                and_count,
                xor_count,
            },
        ))
    }

    /// Loads a circuit from a byte-array in protobuf format
    pub fn load_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        let circ = ProtoCircuit::decode(bytes)?;
        Circuit::try_from(circ).map_err(|_| CircuitError::MappingError)
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
    pub fn input(&self, id: usize) -> Result<Input, CircuitError> {
        self.inputs
            .get(id)
            .cloned()
            .ok_or(CircuitError::InputError(id, self.name.clone()))
    }

    /// Returns input value from id and value
    pub fn input_value(
        &self,
        id: usize,
        value: impl Into<Value>,
    ) -> Result<InputValue, CircuitError> {
        self.input(id)?.to_value(value)
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

    /// Returns all input ids in ascending order
    pub fn input_ids(&self) -> &[usize] {
        &self.input_ids
    }

    /// Returns whether the provided id is a valid input id
    pub fn is_input_id(&self, id: usize) -> bool {
        self.input_ids.binary_search(&id).is_ok()
    }

    /// Returns group corresponding to output id
    pub fn output(&self, id: usize) -> Result<Output, CircuitError> {
        self.outputs
            .get(id)
            .cloned()
            .ok_or(CircuitError::OutputError(id, self.name.clone()))
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

    /// Returns all output ids in ascending order
    pub fn output_ids(&self) -> &[usize] {
        &self.output_ids
    }

    /// Returns whether the provided id is a valid output id
    pub fn is_output_id(&self, id: usize) -> bool {
        self.output_ids.binary_search(&id).is_ok()
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

    /// Evaluates the circuit in plaintext with the provided inputs
    ///
    /// Constant inputs may be provided, but it is not required
    pub fn evaluate(&self, inputs: &[InputValue]) -> Result<Vec<OutputValue>, CircuitError> {
        let mut wires: Vec<Option<bool>> = vec![None; self.len()];

        // Insert constant inputs
        for input in self.const_inputs.iter() {
            let wire_id = input
                .group
                .wires()
                .get(0)
                .ok_or(CircuitError::InvalidCircuit(
                    "Constant input missing wire id".to_string(),
                ))?;
            match input.value_type() {
                ValueType::ConstZero => wires[*wire_id] = Some(false),
                ValueType::ConstOne => wires[*wire_id] = Some(true),
                _ => {
                    return Err(CircuitError::InvalidCircuit(
                        "Constant input isn't a constant type".to_string(),
                    ))
                }
            }
        }

        // Insert input values
        for input in inputs {
            for (value, wire_id) in input.wire_values().into_iter().zip(input.wires()) {
                wires[*wire_id] = Some(value);
            }
        }

        // Evaluate gates
        for gate in self.gates.iter() {
            let (zref, val) = match *gate {
                Gate::Xor {
                    xref, yref, zref, ..
                } => {
                    let x = wires[xref].ok_or(CircuitError::UninitializedWire(xref))?;
                    let y = wires[yref].ok_or(CircuitError::UninitializedWire(yref))?;
                    (zref, x ^ y)
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x = wires[xref].ok_or(CircuitError::UninitializedWire(xref))?;
                    let y = wires[yref].ok_or(CircuitError::UninitializedWire(yref))?;
                    (zref, x & y)
                }
                Gate::Inv { xref, zref, .. } => {
                    let x = wires[xref].ok_or(CircuitError::UninitializedWire(xref))?;
                    (zref, !x)
                }
            };
            wires[zref] = Some(val);
        }

        // Map wires to outputs and convert to values
        let mut outputs: Vec<OutputValue> = Vec::with_capacity(self.output_count());
        for output in self.outputs.iter() {
            let mut value: Vec<bool> = Vec::with_capacity(output.as_ref().len());
            for id in output.as_ref().wires() {
                value.push(wires[*id].ok_or(CircuitError::UninitializedWire(*id))?);
            }
            outputs.push(OutputValue::new(
                output.clone(),
                Value::new(output.value_type(), value)?,
            )?);
        }

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_inputs_must_be_connected() {
        let inputs = vec![Input::new(0, Group::new("", "", ValueType::Bool, &[0]))];
        let gates = vec![Gate::Xor {
            id: 0,
            xref: 0,
            yref: 1,
            zref: 2,
        }];
        let err = Circuit::new("", "", inputs, vec![], gates).unwrap_err();
        assert!(err
            .to_string()
            .contains("All input wires must be mapped to gate inputs"));
    }

    #[test]
    fn test_all_outputs_must_be_connected() {
        let inputs = vec![Input::new(0, Group::new("", "", ValueType::Bool, &[0, 1]))];
        let gates = vec![Gate::Xor {
            id: 0,
            xref: 0,
            yref: 1,
            zref: 2,
        }];
        let outputs = vec![Output::new(0, Group::new("", "", ValueType::Bool, &[3]))];
        let err = Circuit::new("", "", inputs, outputs, gates).unwrap_err();
        assert!(err
            .to_string()
            .contains("All output wires must be mapped to gate outputs"));
    }

    #[test]
    fn test_gate_invariants() {
        // output can't be connected to input
        let gate = Gate::Xor {
            id: 0,
            xref: 0,
            yref: 1,
            zref: 1,
        };
        let err = gate.validate().unwrap_err();
        assert!(matches!(err, CircuitError::InvalidCircuit(_)));
    }
}
