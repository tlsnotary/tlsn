use std::cell::RefCell;

use crate::{builder::BuilderState, types::BinaryRepr};

/// A wrapper type for tracing operations applied to a value.
///
/// This type is used to track the operations applied to a value, which
/// is used to build a circuit via a [`CircuitBuilder`](crate::CircuitBuilder).
#[derive(Clone, Copy)]
pub struct Tracer<'a, T> {
    pub(crate) value: T,
    pub(crate) state: &'a RefCell<BuilderState>,
}

impl<'a, T> Tracer<'a, T> {
    /// Create a new tracer.
    pub fn new(state: &'a RefCell<BuilderState>, value: T) -> Self {
        Self { value, state }
    }

    /// Return the inner value.
    pub fn to_inner(self) -> T {
        self.value
    }
}

impl<'a, T> From<Tracer<'a, T>> for BinaryRepr
where
    T: Into<BinaryRepr>,
{
    fn from(tracer: Tracer<'a, T>) -> Self {
        tracer.value.into()
    }
}

impl<'a, const N: usize, T> From<[Tracer<'a, T>; N]> for BinaryRepr
where
    T: Into<BinaryRepr>,
{
    fn from(tracer: [Tracer<'a, T>; N]) -> Self {
        BinaryRepr::Array(tracer.into_iter().map(|tracer| tracer.into()).collect())
    }
}

impl<'a, T> From<Vec<Tracer<'a, T>>> for BinaryRepr
where
    T: Into<BinaryRepr>,
{
    fn from(tracer: Vec<Tracer<'a, T>>) -> Self {
        BinaryRepr::Array(tracer.into_iter().map(|tracer| tracer.into()).collect())
    }
}
