use core::ops::{BitXor, BitXorAssign};

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Block(u128);

pub const BLOCK_LEN: usize = 16;

impl Block {
    pub fn new(b: u128) -> Self {
        Self(b)
    }

    #[inline]
    pub fn zero() -> Self {
        Self(0)
    }

    #[inline]
    pub fn set_lsb(&mut self) {
        self.0 |= 1;
    }

    #[inline]
    pub fn lsb(&self) -> bool {
        (self.0 & 1) == 1
    }
}

impl BitXor for Block {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_lsb() {
        let mut b = Block::new(2);
        b.set_lsb();
        assert_eq!(Block::new(3), b);
    }

    #[test]
    fn test_lsb() {
        let a = Block::new(0);
        assert_eq!(a.lsb(), false);
        let a = Block::new(1);
        assert_eq!(a.lsb(), true);
        let a = Block::new(2);
        assert_eq!(a.lsb(), false);
        let a = Block::new(3);
        assert_eq!(a.lsb(), true);
    }

    #[test]
    fn test_bitxor() {
        let mut a = Block::new(0);
        let mut b = Block::new(0);
        assert_eq!(a ^ b, Block::new(0));
        a = Block::new(1);
        assert_eq!(a ^ b, Block::new(1));
        b = Block::new(1);
        assert_eq!(a ^ b, Block::new(0));
        a = Block::new(0);
        b = Block::new(1);
        assert_eq!(a ^ b, Block::new(1));
    }
}
