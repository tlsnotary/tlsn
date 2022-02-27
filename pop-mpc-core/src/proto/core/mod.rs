pub mod garble;
pub mod ot;

use crate::utils::parse_ristretto_key;

include!(concat!(env!("OUT_DIR"), "/core.rs"));

impl From<crate::Block> for Block {
    #[inline]
    fn from(b: crate::Block) -> Self {
        Self {
            low: b.inner() as u64,
            high: (b.inner() >> 64) as u64,
        }
    }
}

impl From<Block> for crate::Block {
    #[inline]
    fn from(b: Block) -> Self {
        Self::new(b.low as u128 + ((b.high as u128) << 64))
    }
}

impl From<curve25519_dalek::ristretto::RistrettoPoint> for RistrettoPoint {
    #[inline]
    fn from(p: curve25519_dalek::ristretto::RistrettoPoint) -> Self {
        Self {
            point: p.compress().as_bytes().to_vec(),
        }
    }
}
