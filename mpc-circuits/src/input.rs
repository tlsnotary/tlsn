use std::sync::Arc;

use crate::{error::ValueError, CircuitError, Group, Value, ValueType, WireGroup};

/// Group of wires corresponding to a circuit input
#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    /// Input id of circuit
    id: usize,
    pub(crate) group: Arc<Group>,
}

impl Input {
    /// Creates a new circuit input
    pub(crate) fn new(id: usize, group: Group) -> Self {
        Self {
            id,
            group: Arc::new(group),
        }
    }

    /// Returns input id
    pub fn id(&self) -> usize {
        self.id
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

impl WireGroup for Input {
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

impl AsRef<Group> for Input {
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
                input.name().to_string(),
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
