use std::sync::Arc;

use crate::{Circuit, Group, ValueType, WireGroup};

/// Group of wires corresponding to one circuit output (a circuit may have
/// multiple outputs)
#[derive(Debug, Clone, PartialEq)]
pub struct Output(pub(crate) Arc<Group>);

impl Output {
    /// Creates a new circuit output
    #[inline]
    pub(crate) fn new(group: Group) -> Self {
        Self(Arc::new(group))
    }
}

impl WireGroup for Output {
    fn circuit(&self) -> Arc<Circuit> {
        self.0.circuit()
    }

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
