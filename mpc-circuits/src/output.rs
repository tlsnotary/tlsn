use std::sync::Arc;

use crate::{Group, ValueType, WireGroup};

/// Group of wires corresponding to one circuit output (a circuit may have
/// multiple outputs)
#[derive(Debug, Clone, PartialEq)]
pub struct Output(pub(crate) Arc<Group>);

impl Output {
    /// Creates a new circuit output
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

impl WireGroup for Output {
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

impl AsRef<Group> for Output {
    fn as_ref(&self) -> &Group {
        &self.0
    }
}
