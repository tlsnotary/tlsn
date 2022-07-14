pub mod errors;
pub mod follower;
pub mod leader;

pub use errors::PointAdditionError;
pub use follower::PaillierFollower;
pub use leader::PaillierLeader;

use mpc_core::point_addition::SecretShare;

use async_trait::async_trait;
use mockall::automock;

/// This trait is for securely secret-sharing the addition of two elliptic curve points.
/// Let `P + Q = O = (x, y)`. Each party receives additive shares of the x-coordinate where `x_m + x_s = x`.
#[automock]
#[async_trait]
pub trait PointAddition2PC {
    async fn add(&mut self, point: &p256::EncodedPoint) -> Result<SecretShare, PointAdditionError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_core::point_addition::combine_shares;
    use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use rand::thread_rng;

    #[tokio::test]
    async fn test_point_addition() {
        let (socket_m, socket_s) = tokio::net::UnixStream::pair().unwrap();

        let mut master = PaillierLeader::new(socket_m);
        let mut slave = PaillierFollower::new(socket_s);

        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let master_secret = SecretKey::random(&mut rng);
        let master_point =
            (&server_pk * &master_secret.to_nonzero_scalar()).to_encoded_point(false);

        let slave_secret = SecretKey::random(&mut rng);
        let slave_point = (&server_pk * &slave_secret.to_nonzero_scalar()).to_encoded_point(false);

        let (task_m, task_s) = tokio::join!(
            tokio::spawn(async move { master.add(&master_point).await }),
            tokio::spawn(async move { slave.add(&slave_point).await })
        );

        let master_share = task_m.unwrap().unwrap();
        let slave_share = task_s.unwrap().unwrap();

        let pms = ((&server_pk * &master_secret.to_nonzero_scalar())
            + (&server_pk * &slave_secret.to_nonzero_scalar()))
            .to_affine();

        let pms = *pms.to_encoded_point(false).x().unwrap();

        assert_eq!(pms.to_vec(), combine_shares(master_share, slave_share));
    }
}
