// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Defines a block as a 128-bit value, and implements block-related functions.

#[cfg(feature = "curve25519-dalek")]
use crate::Aes256;
#[cfg(feature = "curve25519-dalek")]
use curve25519_dalek::ristretto::RistrettoPoint;
use std::{
    arch::x86_64::*,
    hash::{Hash, Hasher},
};

/// A 128-bit chunk.
#[derive(Clone, Copy)]
pub struct Block(pub __m128i);

union __U128 {
    vector: __m128i,
    bytes: u128,
}

const ONE: __m128i = unsafe { (__U128 { bytes: 1 }).vector };
const ONES: __m128i = unsafe {
    (__U128 {
        bytes: 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
    })
    .vector
};

impl Block {
    /// Convert into a pointer.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }
    /// Convert into a mutable pointer.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut().as_mut_ptr()
    }

    /// Carryless multiplication.
    ///
    /// This code is adapted from the EMP toolkit's implementation.
    #[inline]
    pub fn clmul(self, rhs: Self) -> (Self, Self) {
        unsafe {
            let x = self.0;
            let y = rhs.0;
            let zero = _mm_clmulepi64_si128(x, y, 0x00);
            let one = _mm_clmulepi64_si128(x, y, 0x10);
            let two = _mm_clmulepi64_si128(x, y, 0x01);
            let three = _mm_clmulepi64_si128(x, y, 0x11);
            let tmp = _mm_xor_si128(one, two);
            let ll = _mm_slli_si128(tmp, 8);
            let rl = _mm_srli_si128(tmp, 8);
            let x = _mm_xor_si128(zero, ll);
            let y = _mm_xor_si128(three, rl);
            (Block(x), Block(y))
        }
    }

    /// Hash an elliptic curve point `pt` and tweak `tweak`.
    ///
    /// Computes the hash by computing `E_{pt}(tweak)`, where `E` is AES-256.
    #[cfg(feature = "curve25519-dalek")]
    #[inline]
    pub fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> Self {
        let k = pt.compress();
        let c = Aes256::new(k.as_bytes());
        c.encrypt(Block::from(tweak))
    }

    /// Return the least significant bit.
    #[inline]
    pub fn lsb(&self) -> bool {
        unsafe { _mm_extract_epi8(_mm_and_si128(self.0, ONE), 0) == 1 }
    }
    /// Set the least significant bit.
    #[inline]
    pub fn set_lsb(&self) -> Block {
        unsafe { Block(_mm_or_si128(self.0, ONE)) }
    }
    /// Flip all bits.
    #[inline]
    pub fn flip(&self) -> Self {
        unsafe { Block(_mm_xor_si128(self.0, ONES)) }
    }

    /// Try to create a `Block` from a slice of bytes. The slice must have exactly 16 bytes.
    #[inline]
    pub fn try_from_slice(bytes_slice: &[u8]) -> Option<Self> {
        if bytes_slice.len() != 16 {
            return None;
        }
        let mut bytes = [0; 16];
        bytes[..16].clone_from_slice(&bytes_slice[..16]);
        Some(Block::from(bytes))
    }
}

impl Default for Block {
    #[inline]
    fn default() -> Self {
        unsafe { Block(_mm_setzero_si128()) }
    }
}

impl PartialEq for Block {
    #[inline]
    fn eq(&self, other: &Block) -> bool {
        unsafe {
            let neq = _mm_xor_si128(self.0, other.0);
            _mm_test_all_zeros(neq, neq) != 0
        }
    }
}

impl Eq for Block {}

impl Ord for Block {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u128::from(*self).cmp(&u128::from(*other))
    }
}

impl PartialOrd for Block {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(u128::from(*self).cmp(&u128::from(*other)))
    }
}

impl AsRef<[u8]> for Block {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        unsafe { &*(self as *const Block as *const [u8; 16]) }
    }
}

impl AsMut<[u8]> for Block {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *(self as *mut Block as *mut [u8; 16]) }
    }
}

impl std::ops::BitAnd for Block {
    type Output = Block;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        unsafe { Block(_mm_and_si128(self.0, rhs.0)) }
    }
}

impl std::ops::BitAndAssign for Block {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        unsafe { self.0 = _mm_and_si128(self.0, rhs.0) }
    }
}

impl std::ops::BitOr for Block {
    type Output = Block;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        unsafe { Block(_mm_or_si128(self.0, rhs.0)) }
    }
}

impl std::ops::BitOrAssign for Block {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        unsafe { self.0 = _mm_or_si128(self.0, rhs.0) }
    }
}

impl std::ops::BitXor for Block {
    type Output = Block;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        unsafe { Block(_mm_xor_si128(self.0, rhs.0)) }
    }
}

impl std::ops::BitXorAssign for Block {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        unsafe { self.0 = _mm_xor_si128(self.0, rhs.0) }
    }
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let block: [u8; 16] = (*self).into();
        for byte in block.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let block: [u8; 16] = (*self).into();
        for byte in block.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl rand::distributions::Distribution<Block> for rand::distributions::Standard {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block::from(rng.gen::<u128>())
    }
}

impl From<Block> for u128 {
    #[inline]
    fn from(m: Block) -> u128 {
        unsafe { *(&m as *const _ as *const u128) }
    }
}

impl From<u128> for Block {
    #[inline]
    fn from(m: u128) -> Self {
        unsafe { std::mem::transmute(m) }
        // XXX: the below doesn't work due to pointer-alignment issues.
        // unsafe { *(&m as *const _ as *const Block) }
    }
}

impl From<Block> for __m128i {
    #[inline]
    fn from(m: Block) -> __m128i {
        m.0
    }
}

impl From<__m128i> for Block {
    #[inline]
    fn from(m: __m128i) -> Self {
        Block(m)
    }
}

impl From<Block> for [u8; 16] {
    #[inline]
    fn from(m: Block) -> [u8; 16] {
        unsafe { *(&m as *const _ as *const [u8; 16]) }
    }
}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(m: [u8; 16]) -> Self {
        unsafe { std::mem::transmute(m) }
        // XXX: the below doesn't work due to pointer-alignment issues.
        // unsafe { *(&m as *const _ as *const Block) }
    }
}

impl From<[u16; 8]> for Block {
    #[inline]
    fn from(m: [u16; 8]) -> Self {
        unsafe { std::mem::transmute(m) }
    }
}

impl From<Block> for [u32; 4] {
    #[inline]
    fn from(m: Block) -> Self {
        unsafe { *(&m as *const _ as *const [u32; 4]) }
    }
}

impl Hash for Block {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let v: u128 = (*self).into();
        v.hash(state);
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct Helperb {
    pub block: u128,
}

#[cfg(feature = "serde")]
impl Serialize for Block {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let helper = Helperb {
            block: <u128>::from(*self),
        };
        helper.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = Helperb::deserialize(deserializer)?;
        Ok(Block::from(helper.block.to_le_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_and() {
        let x = rand::random::<Block>();
        let y = x & Block(ONES);
        assert_eq!(x, y);
    }

    #[test]
    fn test_or() {
        let x = rand::random::<Block>();
        let y = x | Block(ONES);
        assert_eq!(y, Block(ONES));
        let y = x | x;
        assert_eq!(x, y);
    }

    #[test]
    fn test_xor() {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        let z = x ^ y;
        let z = z ^ y;
        assert_eq!(x, z);
    }

    #[test]
    fn test_lsb() {
        let x = rand::random::<Block>();
        let x = x | Block(ONE);
        assert!(x.lsb());
        let x = x ^ Block(ONE);
        assert!(!x.lsb());
    }

    #[test]
    fn test_flip() {
        let x = rand::random::<Block>();
        let y = x.flip().flip();
        assert_eq!(x, y);
    }

    #[test]
    fn test_conversion() {
        let x = rand::random::<u128>();
        let x_ = u128::from(Block::from(x));
        assert_eq!(x, x_);
    }
}
