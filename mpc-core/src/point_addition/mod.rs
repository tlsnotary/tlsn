//! This module implements EC point addition in 2PC using the Paillier
//! cryptosystem.
//!
//! The two parties have their secret points A and B which they
//! want to add. At the end, the parties will have with their shares of the
//! resulting point's X coordinate. (Obtaining the shares of the Y coordinate
//! would also be possible using this approach, but it hasn't been
//! implemented here).
//!
//! For a more comprehensive explanation of this protocol, see our [documentation](https://tlsnotary.github.io/docs-mdbook/)

mod follower;
mod leader;

use std::{convert::TryFrom, ops::Add};

pub use crate::msgs::point_addition::PointAdditionMessage;
use curv::{arithmetic::Converter, BigInt};
pub use follower::{state as follower_state, PointAdditionFollower};
pub use leader::{state as leader_state, PointAdditionLeader};

/// NIST P-256 Prime
pub const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

/// Additive secret share of resulting X coordinate
pub struct P256SecretShare(pub(crate) [u8; 32]);

impl P256SecretShare {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Add<P256SecretShare> for P256SecretShare {
    type Output = Vec<u8>;

    fn add(self, rhs: P256SecretShare) -> Self::Output {
        let x = (BigInt::from_bytes(self.as_bytes()) + BigInt::from_bytes(rhs.as_bytes()))
            % BigInt::from_hex(P).unwrap();
        x.to_bytes()
    }
}

impl TryFrom<BigInt> for P256SecretShare {
    type Error = BigInt;

    fn try_from(share: BigInt) -> Result<Self, BigInt> {
        Ok(Self(share.to_bytes_array::<32>().ok_or(share)?))
    }
}

/// Errors that may occur when using the point_addition module
#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error("Protocol generated invalid P256 key share")]
    InvalidKeyshare,
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand::thread_rng;

    #[test]
    fn test_point_addition() {
        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let leader_secret = SecretKey::random(&mut rng);
        let leader_point =
            (&server_pk * &leader_secret.to_nonzero_scalar()).to_encoded_point(false);

        let follower_secret = SecretKey::random(&mut rng);
        let follower_point =
            (&server_pk * &follower_secret.to_nonzero_scalar()).to_encoded_point(false);

        let leader = PointAdditionLeader::new(&leader_point);
        let follower = PointAdditionFollower::new(&follower_point);

        let (leader_msg, leader) = leader.next();
        let (follower_msg, follower) = follower.next(leader_msg);

        let (leader_msg, leader) = leader.next(follower_msg);
        let (follower_msg, follower) = follower.next(leader_msg);

        let (leader_msg, leader) = leader.next(follower_msg);
        let (follower_msg, follower) = follower.next(leader_msg);

        let leader_share = leader.finalize(follower_msg).unwrap();
        let follower_share = follower.finalize().unwrap();

        let pms = ((&server_pk * &leader_secret.to_nonzero_scalar())
            + (&server_pk * &follower_secret.to_nonzero_scalar()))
            .to_encoded_point(false)
            .x()
            .unwrap()
            .to_vec();

        assert_eq!(pms, leader_share + follower_share);
    }
}
