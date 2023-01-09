use std::sync::Arc;

use crate::{Group, ValueType, WireGroup};

/// Group of wires corresponding to a circuit input
#[derive(Debug, Clone, PartialEq)]
pub struct Input(pub(crate) Arc<Group>);

impl Input {
    /// Creates a new circuit input
    #[inline]
    pub(crate) fn new(
        id: usize,
        name: &str,
        desc: &str,
        value_type: ValueType,
        wires: Vec<usize>,
    ) -> Self {
        Self(Arc::new(Group::new(id, name, desc, value_type, wires)))
    }
}

impl WireGroup for Input {
    #[inline]
    fn id(&self) -> usize {
        self.0.id()
    }

    #[inline]
    fn name(&self) -> &str {
        self.0.name()
    }

    #[inline]
    fn description(&self) -> &str {
        self.0.description()
    }

    #[inline]
    fn value_type(&self) -> ValueType {
        self.0.value_type()
    }

    #[inline]
    fn wires(&self) -> &[usize] {
        self.0.wires()
    }
}

impl AsRef<Group> for Input {
    fn as_ref(&self) -> &Group {
        &self.0
    }
}
