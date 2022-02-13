use cipher::{
    consts::{U16, U32},
    generic_array::GenericArray,
    BlockCipher, BlockEncrypt,
};
use core::ops::{BitAnd, BitXor, BitXorAssign};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{CryptoRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::convert::{From, TryInto};

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Block(u128);

pub const BLOCK_LEN: usize = 16;
pub const BLOCK_ZERO: Block = Block { 0: 0 };
pub const BLOCK_ONES: Block = Block { 0: u128::MAX };
pub const SELECT_MASK: [Block; 2] = [BLOCK_ZERO, BLOCK_ONES];

impl Block {
    #[inline]
    pub fn new(b: u128) -> Self {
        Self(b)
    }

    #[inline]
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }

    #[inline]
    pub fn hash_tweak<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        tweak: usize,
    ) -> Self {
        let gid: [u8; 16] = (tweak as u128).to_be_bytes();
        let label: [u8; 16] = self.to_be_bytes();

        let mut h1: GenericArray<u8, U16> = GenericArray::from(label);
        c.encrypt_block(&mut h1);

        let h2: GenericArray<u8, U16> = GenericArray::clone_from_slice(h1.as_slice());
        let mut h2: GenericArray<u8, U16> = h2.into_iter().zip(gid).map(|(a, b)| a ^ b).collect();
        c.encrypt_block(&mut h2);

        let h3: GenericArray<u8, U16> = GenericArray::clone_from_slice(h2.as_slice());
        let h3: GenericArray<u8, U16> = h3.into_iter().zip(h1).map(|(a, b)| a ^ b).collect();

        let b: [u8; 16] = h3
            .as_slice()
            .try_into()
            .expect("Expected array to have length 16");
        let h: u128 = u128::from_be_bytes(b);
        Self::new(h)
    }

    #[inline]
    pub fn hash_point(point: &RistrettoPoint, tweak: usize) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(point.compress().as_bytes());
        hasher.update(tweak.to_be_bytes());
        let h: [u8; 16] = hasher.finalize()[..16]
            .try_into()
            .expect("Unable to convert hash to block");
        Self::from(h)
    }

    #[inline]
    pub fn zero() -> Self {
        Self(0)
    }

    #[inline]
    pub fn ones() -> Self {
        Self(u128::MAX)
    }

    #[inline]
    pub fn set_lsb(&mut self) {
        self.0 |= 1;
    }

    #[inline]
    pub fn lsb(&self) -> usize {
        ((self.0 & 1) == 1) as usize
    }

    #[inline]
    pub fn to_ne_bytes(&self) -> [u8; 16] {
        self.0.to_ne_bytes()
    }

    #[inline]
    pub fn to_be_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(b: [u8; 16]) -> Self {
        Block::new(u128::from_be_bytes(b))
    }
}

impl From<usize> for Block {
    #[inline]
    fn from(b: usize) -> Self {
        Self(b as u128)
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl BitAnd for Block {
    type Output = Self;

    #[inline]
    fn bitand(self, other: Self) -> Self::Output {
        Self(self.0 & other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_lsb() {
        let mut b = Block::new(0);
        b.set_lsb();
        assert_eq!(Block::new(1), b);
        let mut b = Block::new(2);
        b.set_lsb();
        assert_eq!(Block::new(3), b);
        let mut b = Block::new(1);
        b.set_lsb();
        assert_eq!(Block::new(1), b);
        let mut b = Block::new(3);
        b.set_lsb();
        assert_eq!(Block::new(3), b);
    }

    #[test]
    fn test_lsb() {
        let a = Block::new(0);
        assert_eq!(a.lsb(), 0);
        let a = Block::new(1);
        assert_eq!(a.lsb(), 1);
        let a = Block::new(2);
        assert_eq!(a.lsb(), 0);
        let a = Block::new(3);
        assert_eq!(a.lsb(), 1);
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
