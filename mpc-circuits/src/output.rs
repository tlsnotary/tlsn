use std::sync::Arc;

use crate::{error::ValueError, value::WireGroupValue, Group, Value, ValueType, WireGroup};

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

    /// Converts to [`OutputValue`]
    pub fn to_value(self, value: impl Into<Value>) -> Result<OutputValue, ValueError> {
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
        Ok(OutputValue {
            output: self,
            value,
        })
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
    /// Returns output id
    pub fn id(&self) -> usize {
        self.output.id
    }

    /// Returns [`Output`] corresponding to this value
    pub fn output(&self) -> &Output {
        &self.output
    }

    /// Returns value
    pub fn value(&self) -> &Value {
        &self.value
    }
}

impl WireGroup for OutputValue {
    fn name(&self) -> &str {
        self.output.name()
    }

    fn description(&self) -> &str {
        self.output.description()
    }

    fn value_type(&self) -> ValueType {
        self.output.value_type()
    }

    fn wires(&self) -> &[usize] {
        self.output.wires()
    }
}

impl WireGroupValue for OutputValue {
    fn wire_values(&self) -> Vec<(usize, bool)> {
        self.output
            .wires()
            .iter()
            .copied()
            .zip(self.value.to_bits().into_iter())
            .collect()
    }
}
