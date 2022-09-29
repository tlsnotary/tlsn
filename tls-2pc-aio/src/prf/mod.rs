mod circuits;
mod follower;
mod leader;

use mpc_aio::protocol::garble::GCError;
use utils_aio::Channel;

pub use follower::PRFFollower;
pub use leader::PRFLeader;
pub use tls_2pc_core::msgs::prf::PRFMessage;

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
    use tls_2pc_core::prf::utils::{hmac_sha256, seed_ke, seed_ms};
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

    /// Expands pre-master secret into session key using TLS 1.2 PRF
    /// Returns session keys
    pub fn key_expansion_tls12(
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        pms: &[u8],
    ) -> ([u8; 16], [u8; 16], [u8; 4], [u8; 4]) {
        // first expand pms into ms
        let seed = seed_ms(client_random, server_random);
        let a1 = hmac_sha256(pms, &seed);
        let a2 = hmac_sha256(pms, &a1);
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed);
        let p1 = hmac_sha256(pms, &a1_seed);
        let p2 = hmac_sha256(pms, &a2_seed);
        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..].copy_from_slice(&p2[..16]);

        // expand ms into session keys
        let seed = seed_ke(client_random, server_random);
        let a1 = hmac_sha256(&ms, &seed);
        let a2 = hmac_sha256(&ms, &a1);
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&a1);
        a1_seed[32..].copy_from_slice(&seed);
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&seed);
        let p1 = hmac_sha256(&ms, &a1_seed);
        let p2 = hmac_sha256(&ms, &a2_seed);
        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..].copy_from_slice(&p2[..8]);

        let mut cwk = [0u8; 16];
        cwk.copy_from_slice(&ek[..16]);
        let mut swk = [0u8; 16];
        swk.copy_from_slice(&ek[16..32]);
        let mut civ = [0u8; 4];
        civ.copy_from_slice(&ek[32..36]);
        let mut siv = [0u8; 4];
        siv.copy_from_slice(&ek[36..]);
        (cwk, swk, civ, siv)
    }

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_prf() {
        let (leader_channel, follower_channel) = DuplexChannel::<PRFMessage>::new();
        let (gc_leader, gc_follower) = mock_dualex_pair();
        let leader = PRFLeader::new(Box::new(leader_channel), gc_leader);
        let follower = PRFFollower::new(Box::new(follower_channel), gc_follower);

        let client_random: [u8; 32] = thread_rng().gen();
        let server_random: [u8; 32] = thread_rng().gen();

        let (leader_share, follower_share) = get_shares().await;

        let pms = leader_share + follower_share;

        let (task_leader, task_follower) = tokio::join!(
            tokio::task::spawn_blocking(move || {
                futures::executor::block_on(leader.compute_session_keys(
                    client_random,
                    server_random,
                    leader_share,
                ))
            }),
            tokio::task::spawn_blocking(move || {
                futures::executor::block_on(follower.compute_session_keys(follower_share))
            })
        );

        let (leader_keys, _leader) = task_leader.unwrap().unwrap();
        let (follower_keys, _follower) = task_follower.unwrap().unwrap();

        let cwk = leader_keys
            .cwk()
            .iter()
            .zip(follower_keys.cwk())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();
        let swk = leader_keys
            .swk()
            .iter()
            .zip(follower_keys.swk())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();
        let civ = leader_keys
            .civ()
            .iter()
            .zip(follower_keys.civ())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();
        let siv = leader_keys
            .siv()
            .iter()
            .zip(follower_keys.siv())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        let (expected_swk, expected_cwk, expected_siv, expected_civ) =
            key_expansion_tls12(&client_random, &server_random, &pms);

        assert_eq!(cwk, expected_cwk);
        assert_eq!(swk, expected_swk);
        assert_eq!(civ, expected_civ);
        assert_eq!(siv, expected_siv);
    }
}
