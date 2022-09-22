mod circuits;
mod follower;
mod leader;

use mpc_aio::protocol::garble::GCError;
use tls_2pc_core::msgs::prf::PRFMessage;
use utils_aio::Channel;

pub use follower::PRFFollower;
pub use leader::PRFLeader;

pub type PRFChannel = Box<dyn Channel<PRFMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum PRFError {
    #[error("error occurred during garbled circuit protocol")]
    GCError(#[from] GCError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(PRFMessage),
}

#[cfg(test)]
mod tests {
    use mpc_aio::protocol::{
        garble::exec::dual::mock_dualex_pair,
        point_addition::{P256SecretShare, PaillierFollower, PaillierLeader, PointAddition2PC},
    };
    use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use rand::{thread_rng, Rng};
    use utils_aio::duplex::DuplexChannel;

    use super::*;

    async fn get_shares() -> (P256SecretShare, P256SecretShare) {
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

        (leader_share, follower_share)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_prf() {
        let (leader_channel, follower_channel) = DuplexChannel::<PRFMessage>::new();
        let (gc_leader, gc_follower) = mock_dualex_pair();
        let leader = PRFLeader::new(Box::new(leader_channel), gc_leader);
        let follower = PRFFollower::new(Box::new(follower_channel), gc_follower);

        let client_random: [u8; 32] = thread_rng().gen();
        let server_random: [u8; 32] = thread_rng().gen();

        let (leader_share, follower_share) = get_shares().await;

        let (task_leader, task_follower) = tokio::join!(
            tokio::spawn(async move {
                leader
                    .compute_session_keys(client_random, server_random, leader_share)
                    .await
            }),
            tokio::spawn(async move { follower.compute_session_keys(follower_share).await })
        );

        let leader_keys = task_leader.unwrap().unwrap();
        let follower_keys = task_follower.unwrap().unwrap();

        println!("{:?}", leader_keys.swk());
    }
}
