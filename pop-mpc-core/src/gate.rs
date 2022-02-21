use crate::errors::GateOpsError;

/// Basic components of a circuit.
///
/// `id` represents the gate id.
/// `xref` and `yref` are the wire ids of the gate inputs
/// `zref` is the wire id of the gate output
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Gate {
    Xor {
        id: usize,
        xref: usize,
        yref: usize,
        zref: usize,
    },
    And {
        id: usize,
        xref: usize,
        yref: usize,
        zref: usize,
    },
    Inv {
        id: usize,
        xref: usize,
        zref: usize,
    },
}

/// Trait required for implementor to be evaluated in a circuit
pub trait GateOps: Clone + Copy {
    /// XOR `self` and `x`
    fn xor(&self, x: &Self) -> Result<Self, GateOpsError>;

    /// INV `self`
    fn inv(&self) -> Result<Self, GateOpsError>;

    /// AND `self` and `x`
    fn and(&self, x: &Self) -> Result<Self, GateOpsError>;
}
