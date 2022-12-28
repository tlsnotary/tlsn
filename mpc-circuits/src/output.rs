use std::sync::Arc;

use crate::{error::ValueError, CircuitError, Group, Value, ValueType, WireGroup};

/// Group of wires corresponding to one circuit output (a circuit may have
/// multiple outputs)
#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    /// Output id of circuit
    id: usize,
    pub(crate) group: Arc<Group>,
}

impl Output {
    /// Creates a new circuit output
    pub(crate) fn new(id: usize, group: Group) -> Self {
        Self {
            id,
            group: Arc::new(group),
        }
    }

    /// Returns output id
    pub fn id(&self) -> usize {
        self.id
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

impl WireGroup for Output {
    fn name(&self) -> &str {
        self.group.name()
    }

    fn description(&self) -> &str {
        self.group.description()
    }

    fn value_type(&self) -> ValueType {
        self.group.value_type()
    }

    fn wires(&self) -> &[usize] {
        self.group.wires()
    }
}

impl AsRef<Group> for Output {
    fn as_ref(&self) -> &Group {
        &self.group
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
                output.name().to_string(),
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
