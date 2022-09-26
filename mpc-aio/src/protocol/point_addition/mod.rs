mod follower;
mod leader;

pub use follower::PaillierFollower;
pub use leader::PaillierLeader;

use mpc_core::{
    msgs::point_addition::PointAdditionMessage,
    point_addition::{P256SecretShare, PointAdditionError as CoreError},
};
use utils_aio::Channel;

pub type PAChannel = Box<dyn Channel<PointAdditionMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error("Secret share failed due to io error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Encountered core error: {0:?}")]
    CoreError(#[from] CoreError),
    #[error("Unexpected message")]
    UnexpectedMessage(PointAdditionMessage),
}

use async_trait::async_trait;
use mockall::automock;

/// This trait is for securely secret-sharing the addition of two elliptic curve points.
/// Let `P + Q = O = (x, y)`. Each party receives additive shares of the x-coordinate where `x_m + x_s = x`.
#[automock]
#[async_trait]
pub trait PointAddition2PC {
    async fn add(
        &mut self,
        point: &p256::EncodedPoint,
    ) -> Result<P256SecretShare, PointAdditionError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use rand::thread_rng;
    use utils_aio::duplex::DuplexChannel;

    #[tokio::test]
    async fn test_point_addition() {
        let (leader_channel, follower_channel) = DuplexChannel::new();

        let mut leader = PaillierLeader::new(Box::new(leader_channel));
        let mut follower = PaillierFollower::new(Box::new(follower_channel));

        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let leader_secret = SecretKey::random(&mut rng);
        let leader_point =
            (&server_pk * &leader_secret.to_nonzero_scalar()).to_encoded_point(false);

        let follower_secret = SecretKey::random(&mut rng);
        let follower_point =
            (&server_pk * &follower_secret.to_nonzero_scalar()).to_encoded_point(false);

        let (task_m, task_s) = tokio::join!(
            tokio::spawn(async move { leader.add(&leader_point).await }),
            tokio::spawn(async move { follower.add(&follower_point).await })
        );

        let leader_share = task_m.unwrap().unwrap();
        let follower_share = task_s.unwrap().unwrap();

        let pms = ((&server_pk * &leader_secret.to_nonzero_scalar())
            + (&server_pk * &follower_secret.to_nonzero_scalar()))
            .to_affine()
            .to_encoded_point(false)
            .x()
            .unwrap()
            .to_vec();

        assert_eq!(pms.to_vec(), leader_share + follower_share);
    }
}
