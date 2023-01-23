use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use core::ops::{BitAnd, BitXor};
use rand::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::convert::{From, TryInto};

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Block(u128);

impl Block {
    pub const LEN: usize = 16;
    pub const ZERO: Self = Self(0);
    pub const ONES: Self = Self(u128::MAX);
    pub const SELECT_MASK: [Self; 2] = [Self::ZERO, Self::ONES];

    #[inline]
    pub fn new(b: u128) -> Self {
        Self(b)
    }

    #[inline]
    pub fn inner(&self) -> u128 {
        self.0
    }

    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }

    #[inline]
    pub fn random_vec<R: Rng + CryptoRng + ?Sized>(rng: &mut R, n: usize) -> Vec<Self> {
        let mut blocks = vec![0u128; n];
        rng.fill(blocks.as_mut_slice());
        blocks.into_iter().map(Self::new).collect()
    }

    #[inline]
    // OT extension Sender must break correlation between his 2 masks before
    // using them in 1-out-of-2 Oblivious Transfer. Every pair of masks has
    // a constant correlation: their XOR equals a delta (delta is choice bits
    // in base OT).
    // If masks were used as-is in OT, Receiver could infer bits of delta and break
    // the OT security.
    // For performance reasons, we don't use a hash but a construction which has
    // tweakable correlation robustness (tcr). The GKWY20 paper shows (in
    // Section 7.4) how to achieve tcr using a fixed-key cipher C instead of a
    // hash, i.e. instead of Hash(x, i) we must do C(C(x) xor i) xor C(x).
    pub fn hash_tweak<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &C,
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

    #[inline]
    pub fn to_bits(&self) -> [bool; 128] {
        let bytes: Vec<Vec<bool>> = self
            .to_be_bytes()
            .iter()
            .map(|b| (0..8).map(|i| (1 << i) & b == 1).collect::<Vec<bool>>())
            .collect();
        bytes
            .concat()
            .as_slice()
            .try_into()
            .expect("Could not convert block into bit array")
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
