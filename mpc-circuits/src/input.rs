use std::sync::Arc;

use crate::{error::ValueError, value::WireGroupValue, Group, Value, ValueType, WireGroup};

/// Group of wires corresponding to a circuit input
#[derive(Debug, Clone, PartialEq)]
pub struct Input(pub(crate) Arc<Group>);

impl Input {
    /// Creates a new circuit input
    pub(crate) fn new(
        id: usize,
        name: &str,
        desc: &str,
        value_type: ValueType,
        wires: Vec<usize>,
    ) -> Self {
        Self(Arc::new(Group::new(id, name, desc, value_type, wires)))
    }

    /// Converts to [`InputValue`]
    pub fn to_value(self, value: impl Into<Value>) -> Result<InputValue, ValueError> {
        let value = value.into();
        if self.value_type() != value.value_type() {
            return Err(ValueError::InvalidType(
                self.name().to_string(),
                self.value_type(),
                value.value_type(),
            ));
        } else if self.len() != value.len() {
            return Err(ValueError::InvalidValue(
                self.name().to_string(),
                self.len(),
                value.len(),
            ));
        }
        Ok(InputValue { input: self, value })
    }
}

impl WireGroup for Input {
    fn id(&self) -> usize {
        self.0.id()
    }

    fn name(&self) -> &str {
        self.0.name()
    }

    fn description(&self) -> &str {
        self.0.description()
    }

    fn value_type(&self) -> ValueType {
        self.0.value_type()
    }

    fn wires(&self) -> &[usize] {
        self.0.wires()
    }
}

impl AsRef<Group> for Input {
    fn as_ref(&self) -> &Group {
        &self.0
    }
}

/// Circuit input with corresponding wire values
#[derive(Debug, Clone, PartialEq)]
pub struct InputValue {
    input: Input,
    value: Value,
}

impl InputValue {
    /// Returns input id
    pub fn id(&self) -> usize {
        self.input.id()
    }

    /// Returns [`Input`] corresponding to this value
    pub fn input(&self) -> &Input {
        &self.input
    }

    /// Returns value
    pub fn value(&self) -> &Value {
        &self.value
    }
}

impl WireGroup for InputValue {
    fn id(&self) -> usize {
        self.input.id()
    }

    fn name(&self) -> &str {
        self.input.name()
    }

    fn description(&self) -> &str {
        self.input.description()
    }

    fn value_type(&self) -> ValueType {
        self.input.value_type()
    }

    fn wires(&self) -> &[usize] {
        self.input.wires()
    }
}

impl WireGroupValue for InputValue {
    fn wire_values(&self) -> Vec<(usize, bool)> {
        self.input
            .wires()
            .iter()
            .copied()
            .zip(self.value.to_bits().into_iter())
            .collect()
    }
}
