use super::GateOps;
use crate::errors::GateOpsError;

pub type Bool = u8;

impl GateOps for Bool {
    /// XOR `self` and `x`
    fn xor(&self, x: &Bool) -> Result<Bool, GateOpsError> {
        Ok((self + x) % 2)
    }

    /// INV `self`
    fn inv(&self) -> Result<Bool, GateOpsError> {
        Ok((1 + self) % 2)
    }

    /// AND `self` and `x`
    fn and(&self, x: &Bool) -> Result<Bool, GateOpsError> {
        Ok(self * x)
    }
}

#[test]
fn test_xor() {
    let a: Bool = 1u8;
    let b: Bool = 1u8;
    assert_eq!(a.xor(&b).unwrap(), 0u8);

    let a: Bool = 0u8;
    let b: Bool = 1u8;
    assert_eq!(a.xor(&b).unwrap(), 1u8);

    let a: Bool = 0u8;
    let b: Bool = 0u8;
    assert_eq!(a.xor(&b).unwrap(), 0u8);

    let a: Bool = 1u8;
    let b: Bool = 0u8;
    assert_eq!(a.xor(&b).unwrap(), 1u8);
}

#[test]
fn test_inv() {
    let a: Bool = 1u8;
    assert_eq!(a.inv().unwrap(), 0u8);

    let a: Bool = 0u8;
    assert_eq!(a.inv().unwrap(), 1u8);
}

#[test]
fn test_and() {
    let a: Bool = 1u8;
    let b: Bool = 1u8;
    assert_eq!(a.and(&b).unwrap(), 1u8);

    let a: Bool = 0u8;
    let b: Bool = 1u8;
    assert_eq!(a.and(&b).unwrap(), 0u8);

    let a: Bool = 0u8;
    let b: Bool = 0u8;
    assert_eq!(a.and(&b).unwrap(), 0u8);

    let a: Bool = 1;
    let b: Bool = 0u8;
    assert_eq!(a.and(&b).unwrap(), 0u8);
}
