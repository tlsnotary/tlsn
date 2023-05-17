use aes::BlockDecrypt;
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use core::ops::{BitAnd, BitXor};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::convert::{From, TryInto};
use utils::bits::ToBitsIter;

/// A block of 128 bits
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Block(u128);

impl Block {
    /// The length of a block in bytes
    pub const LEN: usize = 16;
    /// A zero block
    pub const ZERO: Self = Self(0);
    /// A block with all bits set to 1
    pub const ONES: Self = Self(u128::MAX);
    /// A length 2 array of zero and one blocks
    pub const SELECT_MASK: [Self; 2] = [Self::ZERO, Self::ONES];

    /// Create a new block
    #[inline]
    pub fn new(b: u128) -> Self {
        Self(b)
    }

    /// Return the inner representation of the block
    #[inline]
    pub fn inner(&self) -> u128 {
        self.0
    }

    /// Generate a random block using the provided RNG
    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }

    /// Generate a random array of blocks using the provided RNG
    #[inline]
    pub fn random_array<const N: usize, R: Rng + CryptoRng>(rng: &mut R) -> [Self; N] {
        let mut blocks = [0u128; N];
        rng.fill(blocks.as_mut_slice());
        blocks.map(Self::new)
    }

    /// Generate a random vector of blocks using the provided RNG
    #[inline]
    pub fn random_vec<R: Rng + CryptoRng + ?Sized>(rng: &mut R, n: usize) -> Vec<Self> {
        let mut blocks = vec![0u128; n];
        rng.fill(blocks.as_mut_slice());
        blocks.into_iter().map(Self::new).collect()
    }

    /// OT extension Sender must break correlation between his 2 masks before
    /// using them in 1-out-of-2 Oblivious Transfer. Every pair of masks has
    /// a constant correlation: their XOR equals a delta (delta is choice bits
    /// in base OT).
    /// If masks were used as-is in OT, Receiver could infer bits of delta and break
    /// the OT security.
    /// For performance reasons, we don't use a standard hash but a construction which has
    /// tweakable correlation robustness (tcr). The GKWY20 paper shows (in
    /// Section 7.4) how to achieve tcr using a fixed-key cipher C instead of a
    /// hash, i.e. instead of Hash(x, i) we must do C(C(x) xor i) xor C(x).
    #[inline]
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

    /// Encrypts a block using the provided cipher
    #[inline]
    pub fn encrypt<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(&self, cipher: &C) -> Self {
        let mut b = self.to_be_bytes().into();
        cipher.encrypt_block(&mut b);
        Self::new(u128::from_be_bytes(b.into()))
    }

    /// Decrypts a block using the provided cipher
    #[inline]
    pub fn decrypt<C: BlockCipher<BlockSize = U16> + BlockDecrypt>(&self, cipher: &C) -> Self {
        let mut b = self.to_be_bytes().into();
        cipher.decrypt_block(&mut b);
        Self::new(u128::from_be_bytes(b.into()))
    }

    /// Reverses the bits of the block
    #[inline]
    pub fn reverse_bits(self) -> Self {
        Self(self.0.reverse_bits())
    }

    /// Sets the least significant bit of the block
    #[inline]
    pub fn set_lsb(&mut self) {
        self.0 |= 1;
    }

    /// Returns the least significant bit of the block
    #[inline]
    pub fn lsb(&self) -> usize {
        ((self.0 & 1) == 1) as usize
    }

    /// Serializes the block in native-endian format
    #[inline]
    pub fn to_ne_bytes(&self) -> [u8; 16] {
        self.0.to_ne_bytes()
    }

    /// Serializes the block in big-endian format
    #[inline]
    pub fn to_be_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

/// A trait for converting a type to blocks
pub trait BlockSerialize {
    /// The block representation of the type
    type Serialized: std::fmt::Debug + Clone + Copy + Send + Sync + 'static;

    /// Convert the type to blocks
    fn to_blocks(self) -> Self::Serialized;

    /// Convert the blocks to the type
    fn from_blocks(blocks: Self::Serialized) -> Self;
}

impl ToBitsIter for Block {
    type Lsb0Iter = <u128 as ToBitsIter>::Lsb0Iter;

    type Msb0Iter = <u128 as ToBitsIter>::Msb0Iter;

    fn into_lsb0_iter(self) -> Self::Lsb0Iter {
        self.0.into_lsb0_iter()
    }

    fn into_msb0_iter(self) -> Self::Msb0Iter {
        self.0.into_msb0_iter()
    }
}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(b: [u8; 16]) -> Self {
        Block::new(u128::from_be_bytes(b))
    }
}

impl From<Block> for GenericArray<u8, U16> {
    #[inline]
    fn from(b: Block) -> Self {
        b.to_be_bytes().into()
    }
}

impl From<GenericArray<u8, U16>> for Block {
    #[inline]
    fn from(b: GenericArray<u8, U16>) -> Self {
        Block::new(u128::from_be_bytes(b.into()))
    }
}

impl From<Block> for [u8; 16] {
    #[inline]
    fn from(b: Block) -> Self {
        b.to_be_bytes()
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
