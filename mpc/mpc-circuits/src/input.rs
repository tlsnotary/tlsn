use std::sync::Arc;

use crate::{Circuit, Group, GroupId, ValueType, WireGroup};

/// Group of wires corresponding to a circuit input
#[derive(Debug, Clone, PartialEq)]
pub struct Input(pub(crate) Arc<Group>);

impl Input {
    /// Creates a new circuit input
    #[inline]
    pub(crate) fn new(group: Group) -> Self {
        Self(Arc::new(group))
    }
}

impl WireGroup for Input {
    fn circuit(&self) -> Arc<Circuit> {
        self.0.circuit()
    }

    #[inline]
    fn index(&self) -> usize {
        self.0.index()
    }

    #[inline]
    fn id(&self) -> &GroupId {
        self.0.id()
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
