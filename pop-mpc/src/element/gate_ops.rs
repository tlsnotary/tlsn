use crate::errors::GateOpsError;

pub trait GateOps: Clone + Copy {
    /// XOR `self` and `x`
    fn xor(&self, x: &Self) -> Result<Self, GateOpsError>;

    /// INV `self`
    fn inv(&self) -> Result<Self, GateOpsError>;

    /// AND `self` and `x`
    fn and(&self, x: &Self) -> Result<Self, GateOpsError>;
}
