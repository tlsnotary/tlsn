#[cfg(feature = "garble")]
pub mod garble {
    include!(concat!(env!("OUT_DIR"), "/core.garble.rs"));
}
#[cfg(feature = "ot")]
pub mod ot {
    include!(concat!(env!("OUT_DIR"), "/core.ot.rs"));
}

use std::convert::TryInto;

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

impl TryInto<curve25519_dalek::ristretto::RistrettoPoint> for RistrettoPoint {
    type Error = std::io::Error;

    #[inline]
    fn try_into(self) -> Result<curve25519_dalek::ristretto::RistrettoPoint, Self::Error> {
        parse_ristretto_key(self.point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ristretto() {
        let point_a = curve25519_dalek::ristretto::RistrettoPoint::default();
        let proto = RistrettoPoint::from(point_a);
        let point_b: curve25519_dalek::ristretto::RistrettoPoint = proto.try_into().unwrap();
        assert_eq!(point_a, point_b);
    }
}
