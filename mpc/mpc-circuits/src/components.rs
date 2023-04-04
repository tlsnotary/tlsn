use std::{fmt::Display, marker::PhantomData};

/// A binary logic gate.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Gate {
    /// XOR gate.
    Xor {
        x: Node<Sink>,
        y: Node<Sink>,
        z: Node<Feed>,
    },
    /// AND gate.
    And {
        x: Node<Sink>,
        y: Node<Sink>,
        z: Node<Feed>,
    },
    /// Inverter gate.
    Inv { x: Node<Sink>, z: Node<Feed> },
}

impl Gate {
    /// Returns the type of the gate.
    pub fn gate_type(&self) -> GateType {
        match self {
            Gate::Xor { .. } => GateType::Xor,
            Gate::And { .. } => GateType::And,
            Gate::Inv { .. } => GateType::Inv,
        }
    }

    /// Returns the x input of the gate.
    pub fn x(&self) -> Node<Sink> {
        match self {
            Gate::Xor { x, .. } => *x,
            Gate::And { x, .. } => *x,
            Gate::Inv { x, .. } => *x,
        }
    }

    /// Returns the y input of the gate.
    pub fn y(&self) -> Option<Node<Sink>> {
        match self {
            Gate::Xor { y, .. } => Some(*y),
            Gate::And { y, .. } => Some(*y),
            Gate::Inv { .. } => None,
        }
    }

    /// Returns the z output of the gate.
    pub fn z(&self) -> Node<Feed> {
        match self {
            Gate::Xor { z, .. } => *z,
            Gate::And { z, .. } => *z,
            Gate::Inv { z, .. } => *z,
        }
    }

    /// Shifts all the node IDs of the gate by the given offset.
    #[inline]
    pub(crate) fn shift_left(&mut self, offset: usize) {
        match self {
            Gate::Xor { x, y, z } => {
                x.id -= offset;
                y.id -= offset;
                z.id -= offset;
            }
            Gate::And { x, y, z } => {
                x.id -= offset;
                y.id -= offset;
                z.id -= offset;
            }
            Gate::Inv { x, z } => {
                x.id -= offset;
                z.id -= offset;
            }
        }
    }
}

/// The type of a gate.
#[derive(Debug, Clone, Copy)]
pub enum GateType {
    /// XOR gate.
    Xor,
    /// AND gate.
    And,
    /// Inverter gate.
    Inv,
}

/// A feed in a circuit.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Feed;

/// A sink in a circuit.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Sink;

/// A node in a circuit.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Node<T> {
    pub(crate) id: usize,
    _pd: std::marker::PhantomData<T>,
}

impl Display for Node<Feed> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Feed({})", self.id)
    }
}

impl Display for Node<Sink> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sink({})", self.id)
    }
}

impl<T> Node<T> {
    #[inline(always)]
    pub(crate) fn new(id: usize) -> Self {
        Self {
            id,
            _pd: PhantomData,
        }
    }

    /// Returns the id of the node.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Shifts the node ID by the given offset.
    pub(crate) fn shift_left(&mut self, offset: usize) {
        self.id -= offset;
    }
}

impl<T> AsRef<Node<T>> for Node<T> {
    fn as_ref(&self) -> &Node<T> {
        self
    }
}

impl From<Node<Feed>> for Node<Sink> {
    fn from(node: Node<Feed>) -> Self {
        Self {
            id: node.id,
            _pd: PhantomData,
        }
    }
}

impl From<Node<Sink>> for Node<Feed> {
    fn from(node: Node<Sink>) -> Self {
        Self {
            id: node.id,
            _pd: PhantomData,
        }
    }
}
